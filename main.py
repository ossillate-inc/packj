from __future__ import print_function
import sys
import os
import json

from static_proxy.py_analyzer import PyAnalyzer
from pm_proxy.pypi import PypiProxy

from util.net import download_file
from util.dates import datetime_delta
from util.email_validity import check_email_address
from util.files import read_from_csv
from util.enum_util import PackageManagerEnum, LanguageEnum, DistanceAlgorithmEnum, TraceTypeEnum, DataTypeEnum

from parse_apis import parse_api_usage

def get_static_proxy_for_language(language):
	if language == LanguageEnum.python:
		return PyAnalyzer()
	else:
		raise Exception("Proxy not available for language: %s" % language)

def get_pm_proxy_for_language(language, registry=None, cache_dir=None, isolate_pkg_info=False):
	if language == LanguageEnum.python:
		return PypiProxy(registry=registry, cache_dir=cache_dir, isolate_pkg_info=isolate_pkg_info)
	else:
		raise Exception("Proxy not available for language: %s" % language)

def get_threat_model(filename='threats.csv'):
	threat_model = {}
	for line in read_from_csv(filename, skip_header=True):
		typ = line[0]
		attr = line[1].strip('\n')
		threat_model[attr] = typ
	return threat_model

def alert_user(alert_type, threat_model, reason, risks):
	if alert_type in threat_model:
		risk_cat = threat_model[alert_type]
		if risk_cat not in risks:
			risks[risk_cat] = []
		risks[risk_cat].append(reason)
	return risks

def analyze_version(pkg_name, ver_str=None, ver_info=None, pkg_info=None, risks={}):
	try:
		print("[+] Checking version...", end='')

		if not ver_info:
			ver_info = pm_proxy.get_version(pkg_name, ver_str=ver_str, pkg_info=pkg_info)
		assert ver_info, "No version info!"

		# check upload timestamp
		try:
			uploaded = ver_info['uploaded']
			days = datetime_delta(uploaded, days=True)
		except KeyError:
			uploaded = None

		if not uploaded or days > 365:
			reason = 'no release date' if not uploaded else '%d days old' % (days)
			alert_type = 'old package'
			risks = alert_user(alert_type, threat_model, reason, risks)
		print("OK [%d days old]" % (days))
	except Exception as e:
		print("FAILED [%s]" % (str(e)))
	finally:
		return risks

def analyze_cves(pm_name, pkg_name, ver_str, risks={}):
	try:
		print("[+] Checking for CVEs...", end='')
		from osv import get_pkgver_vulns
		vuln_list = get_pkgver_vulns(pm_name, pkg_name, ver_str)
		if vuln_list:
			alert_type = 'contains known vulnerablities (CVEs)'
			reason = 'contains %s' % (','.join(vul['id'] for vul in vuln_list))
			risks = alert_user(alert_type, threat_model, reason, risks)
		else:
			vuln_list = []
		print("OK [%s found]" % (len(vuln_list)))
	except Exception as e:
		print("FAILED [%s]" % (str(e)))
	finally:
		return risks

def analyze_homepage(pkg_name, ver_str=None, pkg_info=None, risks={}):
	try:
		print("[+] Checking homepage...", end='')
		url = pm_proxy.get_homepage(pkg_name, ver_str=ver_str, pkg_info=pkg_info)
		if not url:
			reason = 'no homepage'
			alert_type = 'invalid or no homepage'
			risks = alert_user(alert_type, threat_model, reason, risks)
		elif url in ['example', 'google', 'pastebin', 'amazon', 'yahoo', 'netflix', 'facebook']:
			reason = 'invalid homepage'
			alert_type = 'invalid or no homepage'
			risks = alert_user(alert_type, threat_model, reason, risks)
		print("OK [%s]" % (url))
	except Exception as e:
		print("FAILED [%s]" % (str(e)))
	finally:
		return risks

def analyze_repo(pkg_name, ver_str=None, pkg_info=None, risks={}):
	try:
		print("[+] Checking repo...", end='')
		repo = pm_proxy.get_repo(pkg_name, ver_str=ver_str, pkg_info=pkg_info)
		if not repo:
			repo = pm_proxy.get_homepage(pkg_name, ver_str=ver_str, pkg_info=pkg_info)
		if not repo:
			alert_type = 'no or invalid source repo'
			alert_type = 'no source repo'
			risks = alert_user(alert_type, threat_model, reason, risks)
		elif not repo.startswith('https://github.com') and not repo.startswith('https://gitlab.com'):
			reason = 'invalid source repo'
			alert_type = 'no or invalid source repo'
			risks = alert_user(alert_type, threat_model, reason, risks)
		elif repo.strip('/') in ['https://github.com/pypa/sampleproject', 'https://github.com/kubernetes/kubernetes']:
			reason = 'invalid source repo'
			alert_type = 'no or invalid source repo'
			risks = alert_user(alert_type, threat_model, reason, risks)
		print("OK [%s]" % (repo))
	except Exception as e:
		print("FAILED [%s]" % (str(e)))
	finally:
		return risks

def analyze_readme(pkg_name, ver_str=None, pkg_info=None, risks={}):
	try:
		print("[+] Checking readme...", end='')
		descr = pm_proxy.get_description(pkg_name, ver_str=ver_str, pkg_info=pkg_info)
		if not descr or len(descr) < 100:
			reason = 'no description' if not descr else 'insufficient description'
			alert_type = 'no or insufficient readme'
			risks = alert_user(alert_type, threat_model, reason, risks)
		print("OK [%d bytes]" % (len(descr)))
	except Exception as e:
		print("FAILED [%s]" % (str(e)))
	finally:
		return risks

def analyze_author(pkg_name, ver_str=None, pkg_info=None, risks={}):
	try:
		print("[+] Checking author...", end='')
		author_info = pm_proxy.get_author(pkg_name, ver_str=ver_str, pkg_info=pkg_info)
		assert author_info, "No author info!"

		try:
			email = author_info['email']
		except KeyError:
			email = None

		# check author email
		valid, valid_with_dns = check_email_address(email)
		if not valid or not valid_with_dns:
			alert_type = 'invalid author email (2FA not enabled)'
			reason = 'invalid author email' if not valid else 'expired author email domain'
			risks = alert_user(alert_type, threat_model, reason, risks)
		print("OK [%s]" % (email))
	except Exception as e:
		print("FAILED [%s]" % (str(e)))
	finally:
		return risks

def analyze_apis(pm_name, pkg_name, ver_info, filepath, risks={}):
	try:
		print("[+] Analyzing APIs...", end='')
		if pm_name == 'pypi':
			language=LanguageEnum.python
			configpath = os.path.join('config','astgen_python_smt.config')
		else:
			raise "%s not supported!"

		static = get_static_proxy_for_language(language=language)
		try:
			static.astgen(inpath=filepath, outfile=filepath+'.out', root=None, configpath=configpath,
				pkg_name=pkg_name, pkg_version=ver_str, evaluate_smt=True)
		except:
			if not os.path.exists(filepath+'.out'):
				raise Exception("no output!")

		perms = parse_api_usage(pm_name, filepath+'.out')
		assert perms, "No APIs found!"

		for p in perms:
			if p == "SOURCE_FILE":
				alert_type = 'accesses files and dirs'
				reason = 'reads files and dirs'
				risks = alert_user(alert_type, threat_model, reason, risks)
			elif p == "SINK_FILE":
				alert_type = 'accesses files and dirs'
				reason = 'writes to files and dirs'
				risks = alert_user(alert_type, threat_model, reason, risks)
			elif p == "SINK_NETWORK":
				alert_type = 'communicates with external network'
				reason = 'sends data over the network'
				risks = alert_user(alert_type, threat_model, reason, risks)
			elif p == "SOURCE_NETWORK":
				alert_type = 'communicates with external network'
				reason = 'fetches data over the network'
				risks = alert_user(alert_type, threat_model, reason, risks)
			elif p == "SOURCE_ENVVAR":
				alert_type = 'accesses environment variables'
				reason = 'reads environment variables'
				risks = alert_user(alert_type, threat_model, reason, risks)
			elif p == "SINK_CODE_GENERATION":
				alert_type = 'generates new code at runtime'
				reason = 'generates new code at runtime'
				risks = alert_user(alert_type, threat_model, reason, risks)
		print("OK")
	except Exception as e:
		print("FAILED [%s]" % (str(e)))
	finally:
		return risks

if __name__ == "__main__":
	from static_util import astgen

	threat_model = get_threat_model()

	pm_name = sys.argv[1].lower()
	if pm_name != 'pypi':
		print("Only PyPI is supported. Exiting")
		exit(1)

	ver_str = None
	pkg_name = sys.argv[2]
	if '==' in pkg_name:
		pkg_name, ver_str = pkg_name.split('==')

	try:
		language=LanguageEnum.python
		pm_proxy = get_pm_proxy_for_language(language=language, cache_dir=None, isolate_pkg_info=False)

		print("[+] Fetching '%s' from %s..." % (pkg_name, pm_name), end='')
		pkg_info = pm_proxy.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
		assert pkg_info, "package not found!"

		ver_info = pm_proxy.get_version(pkg_name, ver_str=ver_str, pkg_info=pkg_info)
		assert ver_info, "No version info!"

		ver_str = ver_info['tag']
		print("OK [ver %s]" % (ver_str))
	except Exception as e:
		print("FAILED [%s]" % (str(e)))
		exit(1)

	risks = {}

	risks = analyze_author(pkg_name, ver_str=ver_str, pkg_info=pkg_info, risks=risks)
	risks = analyze_version(pkg_name, ver_str=ver_str, ver_info=ver_info, pkg_info=pkg_info, risks=risks)
	risks = analyze_readme(pkg_name, ver_str=ver_str, pkg_info=pkg_info, risks=risks)
	risks = analyze_repo(pkg_name, ver_str=ver_str, pkg_info=pkg_info, risks=risks)
	risks = analyze_homepage(pkg_name, ver_str=ver_str, pkg_info=pkg_info, risks=risks)
	risks = analyze_cves(pm_name, pkg_name, ver_str=ver_str, risks=risks)

	# download package
	try:
		print("[+] Downloading package '%s' (ver %s) from %s..." % (pkg_name, ver_str, pm_name), end='')
		filepath, size = download_file(ver_info['url'])
		print("OK [%0.2f KB]" % (float(size)/1024))
	except Exception as e:
		print("FAILED [%s]" % (str(e)))

	if filepath:
		risks = analyze_apis(pm_name, pkg_name, ver_info, filepath, risks)

	if not len(risks):
		print("[+] No risks found!")
	else:
		print("[+] %d risk(s) found, package is %s!" % (sum(len(v) for v in risks.values()), ', '.join(risks.keys())))
		print(json.dumps(risks, indent=4))
		print("=> View detailed and complete report at https://packj.dev/%s/%s/%s" % (pm_name, pkg_name, ver_str))
