#!/usr/bin/env python

from __future__ import print_function
import sys
import os
import logging

from util.net import __parse_url, download_file, check_site_exist, check_domain_popular
from util.dates import datetime_delta
from util.email_validity import check_email_address
from util.files import write_json_to_file, read_from_csv
from util.enum_util import PackageManagerEnum, LanguageEnum
from util.formatting import human_format
from util.repo import git_clone, replace_last

from parse_apis import parse_api_usage
from parse_composition import parse_package_composition
from pm_util import get_pm_proxy
from static_util import get_static_proxy_for_language
from static_proxy.static_base import Language2Extensions
from parse_repo import fetch_repo_data

# sys.version_info[0] is the major version number. sys.version_info[1] is minor
if sys.version_info[0] != 3:
	print("\n*** WARNING *** Please use Python 3! Exiting.")
	exit(1)

THREAT_MODEL = {}

def build_threat_model(filename='threats.csv'):
	for line in read_from_csv(filename, skip_header=True):
		typ = line[0]
		attr = line[1].strip('\n')
		THREAT_MODEL[attr] = typ

def alert_user(alert_type, threat_model, reason, risks):
	if alert_type in threat_model:
		risk_cat = threat_model[alert_type]
		if risk_cat not in risks:
			risks[risk_cat] = []
		item = '%s: %s' % (alert_type, reason)
		if item not in risks[risk_cat]:
			risks[risk_cat].append(item)
	return risks

def analyze_release_history(pm_proxy, pkg_name, pkg_info, risks, report):
	try:
		print("\t[+] Checking release history...", end='', flush=True)

		# get package release history
		release_history = pm_proxy.get_release_history(pkg_name, pkg_info=pkg_info)
		assert release_history, "no data!"

		if len(release_history) <= 2:
			reason = 'only %s versions released' % (len(release_history))
			alert_type = 'few versions or releases'
			risks = alert_user(alert_type, THREAT_MODEL, reason, risks)

		print("OK [%d version(s)]" % (len(release_history)))
		report['num_releases'] = len(release_history)
	except Exception as e:
		print("FAILED [%s]" % (str(e)))
	finally:
		return risks, report

def analyze_release_time(pm_proxy, pkg_name, ver_str, pkg_info, risks, report):
	try:
		print("\t[+] Checking release time gap...", end='', flush=True)

		# get package release history
		release_history = pm_proxy.get_release_history(pkg_name, pkg_info=pkg_info)
		assert release_history, "no data!"

		days = release_history[ver_str]['days_since_last_release']

		# check if the latest release is made after a long gap (indicative of package takeover)
		if days and days > 180:
			reason = 'version released after %d days' % (days)
			alert_type = 'version release after a long gap'
			risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
			print("ALERT [%s]" % ('%d days since last release' % (days) if days else 'first release'))
		else:
			print("OK [%s]" % ('%d days since last release' % (days) if days else 'first release'))
	except Exception as e:
		print("FAILED [%s]" % (str(e)))
	finally:
		return risks, report

def analyze_pkg_descr(pm_proxy, pkg_name, ver_str, pkg_info, risks, report):
	try:
		print("\t[+] Checking package description...", end='', flush=True)
		descr = pm_proxy.get_description(pkg_name, ver_str=ver_str, pkg_info=pkg_info)
		if not descr:
			reason = 'no description'
			alert_type = 'no description'
			risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
			print("ALERT [%s]" % (reason))
		else:
			print("OK [%s]" % (descr))
	except Exception as e:
		print("FAILED [%s]" % (str(e)))
	finally:
		return risks, report

def analyze_version(ver_info, risks, report):
	try:
		print("[+] Checking version...", end='', flush=True)

		assert ver_info, "no data!"

		# check upload timestamp
		try:
			uploaded = ver_info['uploaded']
			days = datetime_delta(uploaded, days=True)
		except KeyError:
			raise Exception('parse error')

		# check if the latest release is too old (unmaintained package)
		if not uploaded or days > 365:
			reason = 'no release date' if not uploaded else '%d days old' % (days)
			alert_type = 'old package'
			risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
			print("ALERT [%d days old]" % (days))
		else:
			print("OK [%d days old]" % (days))
		report["version"] = ver_info
	except Exception as e:
		print("FAILED [%s]" % (str(e)))
	finally:
		return risks, report

def analyze_cves(pm_name, pkg_name, ver_str, risks, report):
	try:
		print("[+] Checking for CVEs...", end='', flush=True)
		from osv import get_pkgver_vulns
		vuln_list = get_pkgver_vulns(pm_name, pkg_name, ver_str)
		if vuln_list:
			alert_type = 'contains known vulnerablities (CVEs)'
			reason = 'contains %s' % (','.join(vul['id'] for vul in vuln_list))
			risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
			print("ALERT [%s found]" % (len(vuln_list)))
		else:
			vuln_list = []
			print("OK [none found]")
		report["vulnerabilities"] = vuln_list
	except Exception as e:
		print("FAILED [%s]" % (str(e)))
	finally:
		return risks, report

def analyze_deps(pm_proxy, pkg_name, ver_str, pkg_info, ver_info, risks, report):
	try:
		print("[+] Checking dependencies...", end='', flush=True)
		deps = pm_proxy.get_dependencies(pkg_name, ver_str=ver_str, pkg_info=pkg_info, ver_info=ver_info)
		if deps and len(deps) > 10:
			alert_type = 'too many dependencies'
			reason = '%d found' % (len(deps))
			risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
			print("ALERT [%s]" % (reason))
		else:
			print("OK [%s]" % ('%d direct' % (len(deps)) if deps else 'none found'))
	except Exception as e:
		print("FAILED [%s]" % (str(e)))
	finally:
		return risks, report

def analyze_downloads(pm_proxy, pkg_name, risks, report):
	try:
		print("[+] Checking downloads...", end='', flush=True)
		ret = pm_proxy.get_downloads(pkg_name)
		if ret < 1000:
			reason = 'only %d weekly downloads' % (ret)
			alert_type = 'few downloads'
			risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
		print("OK [%s weekly]" % (human_format(ret)))
	except Exception as e:
		print("FAILED [%s]" % (str(e)))
	finally:
		return risks, report

def analyze_homepage(pm_proxy, pkg_name, ver_str, pkg_info, risks, report):
	try:
		print("[+] Checking homepage...", end='', flush=True)
		url = pm_proxy.get_homepage(pkg_name, ver_str=ver_str, pkg_info=pkg_info)
		if not url:
			reason = 'no homepage'
			alert_type = 'invalid or no homepage'
			risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
		else:
			# check if insecure
			ret = __parse_url(url)
			if ret.scheme != 'https':
				reason = 'insecure webpage'
				alert_type = 'invalid or no homepage'
				risks = alert_user(alert_type, THREAT_MODEL, reason, risks)

			# check if an existent webpage
			valid_site, reason = check_site_exist(url)
			if not valid_site:
				alert_type = 'invalid or no homepage'
				risks = alert_user(alert_type, THREAT_MODEL, reason, risks)

			# check if a popular webpage
			elif check_domain_popular(url):
				reason = 'invalid (popular) webpage'
				alert_type = 'invalid or no homepage'
				risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
		print("OK [%s]" % (url))
		report["homepage"] = url
	except Exception as e:
		print("FAILED [%s]" % (str(e)))
	finally:
		return risks, report

def analyze_repo_descr(risks, report):
	try:
		print("\t[+] Checking repo description...", end='', flush=True)
		descr = report['repo']['description']
		print("OK [%s]" % (descr))
	except Exception as e:
		print("FAILED [%s]" % (str(e)))
	finally:
		return risks, report

def analyze_repo_data(risks, report):
	try:
		repo_url = report['repo']['url']
		print("\t[+] Checking repo data...", end='', flush=True)
		err, repo_data  = fetch_repo_data(repo_url)
		assert repo_data, err

		try:
			num_forks = repo_data['num_forks']
		except KeyError:
			num_forks = None

		try:
			num_stars = repo_data['num_stars']
		except KeyError:
			num_stars = None

		try:
			forked_from = repo_data['forked_from']
		except KeyError:
			forked_from = None

		if num_forks and num_forks < 5:
			alert_type = 'few source repo forks'
			reason = 'only %d forks' % (num_forks)
			risks = alert_user(alert_type, THREAT_MODEL, reason, risks)

		if num_stars and num_stars < 10:
			alert_type = 'few source repo stars'
			reason = 'only %d stars' % (num_stars)
			risks = alert_user(alert_type, THREAT_MODEL, reason, risks)

		print("OK [stars: %d, forks: %d]" % (num_stars, num_forks))
		report['repo'].update(repo_data)
	except Exception as e:
		print("FAILED [%s]" % (str(e)))

	if not repo_data:
		return risks, report

	try:
		print("\t[+] Checking if repo is a forked copy...", end='', flush=True)
		if forked_from:
			alert_type = 'source repo is a forked copy'
			reason = 'forked from %s' % (forked_from)
			risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
			print("OK [forked from %s]" % forked_from)
		else:
			print("OK [original, not forked]")
	except Exception as e:
		print("FAILED [%s]" % (str(e)))
	finally:
		return risks, report

def analyze_repo_activity(risks, report):
	try:
		repo_url = report['repo']['url']
		print("\t[+] Checking repo activity...", end='', flush=True)
		reason, repo_data = git_clone(repo_url)
		if reason:
			alert_type = 'invalid or no source repo'
			risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
			print("ALERT [%s]" % (reason))
		elif repo_data:
			print("OK [commits: %d, contributors: %d, tags: %d]" % \
				(repo_data['commits'], repo_data['contributors'], repo_data['tags']))
			report['repo'].update(repo_data)
	except Exception as e:
		print("FAILED [%s]" % (str(e)))
	finally:
		return risks, report

def analyze_repo_url(pm_proxy, pkg_name, ver_str, pkg_info, ver_info, risks, report):
	try:
		print("[+] Checking repo URL...", end='', flush=True)
		popular_hosting_services = ['https://github.com/','https://gitlab.com/','git+https://github.com/','git://github.com/','https://bitbucket.com/']
		repo_url = pm_proxy.get_repo(pkg_name, ver_str=ver_str, pkg_info=pkg_info, ver_info=ver_info)
		if not repo_url:
			repo_url = pm_proxy.get_homepage(pkg_name, ver_str=ver_str, pkg_info=pkg_info)
			if not repo_url or not repo_url.startswith(tuple(popular_hosting_services)):
				repo_url = None
		if not repo_url:
			repo_url = pm_proxy.get_download_url(pkg_name, ver_str=ver_str, pkg_info=pkg_info)
			if not repo_url or not repo_url.startswith(tuple(popular_hosting_services)):
				repo_url = None
		if repo_url:
			if repo_url.startswith('git+https://'):
				repo_url = repo_url.lstrip('git+')
			if repo_url.startswith('git://'):
				repo_url = repo_url.replace('git://','https://')
			if repo_url.startswith('git+ssh://git@'):
				repo_url = repo_url.replace('git+ssh://git@','https://')
			if repo_url.endswith('.git'):
				repo_url = replace_last(repo_url, '.git', '')
		if not repo_url:
			reason = 'no source repo found'
			alert_type = 'invalid or no source repo'
			risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
		elif not repo_url.startswith(tuple(popular_hosting_services)):
			reason = 'invalid source repo %s' % (repo_url)
			alert_type = 'invalid or no source repo'
			risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
		print("OK [%s]" % (repo_url))
		report["repo"] = {
			"url" : repo_url,
		}
	except Exception as e:
		print("FAILED [%s]" % (str(e)))
	finally:
		return risks, report

def analyze_readme(pm_proxy, pkg_name, ver_str, pkg_info, risks, report):
	try:
		print("[+] Checking readme...", end='', flush=True)
		readme = pm_proxy.get_readme(pkg_name, ver_str=ver_str, pkg_info=pkg_info)
		if not readme or len(readme) < 100:
			reason = 'no readme' if not readme else 'insufficient readme'
			alert_type = 'no or insufficient readme'
			risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
			print("ALERT [%s]" % (reason))
		else:
			print("OK [%d bytes]" % (len(readme)))
	except Exception as e:
		print("FAILED [%s]" % (str(e)))
	finally:
		return risks, report

def analyze_author(pm_proxy, pkg_name, ver_str, pkg_info, ver_info, risks, report):
	try:
		print("[+] Checking author...", end='', flush=True)

		# check author/maintainer email
		author_info = pm_proxy.get_author(pkg_name, ver_str=ver_str, pkg_info=pkg_info, ver_info=ver_info)
		assert author_info, "no data!"

		try:
			email = author_info['email']
		except KeyError:
			email = None

		report["author"] = author_info
		print("OK [%s]" % (email))
	except Exception as e:
		print("FAILED [%s]" % (str(e)))
		return risks, report

	try:
		print("\t[+] Checking email/domain validity...", end='', flush=True)
		if email:
			email = email.replace(' ','')
			if isinstance(email, list):
				email_list = email
			elif isinstance(email, str):
				if ',' in email:
					email_list = email.split(',')
				elif ' ' in email:
					email_list = email.split(' ')
				elif ';' in email:
					email_list = email.split(';')
				else:
					email_list = [email]
			else:
				raise Exception("parse error!")
			for item in email_list:
				try:
					valid, valid_with_dns = check_email_address(item)
				except Exception as ee:
					logging.debug("Failed to parse email %s: %s" % (item, str(ee)))
					valid = False
				if not valid or not valid_with_dns:
					break

		if not email or not valid or not valid_with_dns:
			alert_type = 'invalid or no author email (2FA not enabled)'
			reason = 'no email' if not email else 'invalid author email' if not valid else 'expired author email domain'
			risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
			print("ALERT [%s]" % (reason))
		else:
			print("OK [%s]" % (email))
	except Exception as e:
		print("FAILED [%s]" % (str(e)))
	finally:
		return risks, report

def analyze_composition(pm_name, pkg_name, ver_str, filepath, risks, report):
	try:
		print("[+] Checking files/funcs...", end='', flush=True)

		if pm_name == 'pypi':
			language=LanguageEnum.python
		elif pm_name == 'npm':
			language=LanguageEnum.javascript
		else:
			raise Exception("Package manager %s not supported!")

		num_files, lang_files, num_funcs, total_loc = parse_package_composition(pkg_name, ver_str, filepath + '.out.json')
		lang_file_ext = ','.join(Language2Extensions[language])

		print("OK [%s files (%d %s), %s funcs, LoC: %s]" % \
				(num_files, lang_files, lang_file_ext, num_funcs, human_format(total_loc)))
		report["composition"] = {
			"num_files" : num_files,
			"num_funcs" : num_funcs,
			"%s_files" % (lang_file_ext) : lang_files,
			"Loc"		: total_loc,
		}
	except Exception as e:
		print("FAILED [%s]" % (str(e)))
	finally:
		return risks, report

def analyze_apis(pm_name, pkg_name, ver_str, filepath, risks, report):
	try:
		print("[+] Analyzing code...", end='', flush=True)
		if pm_name == 'pypi':
			language=LanguageEnum.python
			configpath = os.path.join('config','astgen_python_smt.config')
		elif pm_name == 'npm':
			language=LanguageEnum.javascript
			configpath = os.path.join('config','astgen_javascript_smt.config')
		else:
			raise Exception("Package manager %s not supported!")

		static = get_static_proxy_for_language(language=language)
		try:
			static.astgen(inpath=filepath, outfile=filepath+'.out', root=None, configpath=configpath,
				pkg_name=pkg_name, pkg_version=ver_str, evaluate_smt=False)
		except Exception as ee:
			logging.debug("Failed to parse: %s" % (str(ee)))
			raise Exception("parse error")

		assert os.path.exists(filepath+'.out'), "parse error!"

		perms = parse_api_usage(pm_name, filepath+'.out')
		if not perms:
			print("OK [no perms found]")
			return risks, report

		report_data = {}
		perms_needed = set()
		for p, usage in perms.items():
			if p == "SOURCE_FILE":
				alert_type = 'accesses files and dirs'
				reason = 'reads files and dirs'
				risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
				perms_needed.add('file')
			elif p == "SINK_FILE":
				alert_type = 'accesses files and dirs'
				reason = 'writes to files and dirs'
				risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
				perms_needed.add('file')
			elif p == "SINK_NETWORK":
				alert_type = 'communicates with external network'
				reason = 'sends data over the network'
				risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
				perms_needed.add('network')
			elif p == "SOURCE_NETWORK":
				alert_type = 'communicates with external network'
				reason = 'fetches data over the network'
				risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
				perms_needed.add('network')
			elif p == "SINK_CODE_GENERATION":
				alert_type = 'generates new code at runtime'
				reason = 'generates new code at runtime'
				risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
				perms_needed.add('codegen')
			elif p == "SINK_PROCESS_OPERATION":
				alert_type = 'forks or exits OS processes'
				reason = 'performs a process operation'
				risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
				perms_needed.add('process')
			elif p == "SOURCE_OBFUSCATION":
				alert_type = 'accesses obfuscated (hidden) code'
				reason = 'reads hidden code'
				risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
				perms_needed.add('decode')
			elif p == "SOURCE_SETTINGS":
				alert_type = 'accesses system/environment variables'
				reason = 'reads system settings or environment variables'
				risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
				perms_needed.add('envvars')
			elif p == "SINK_UNCLASSIFIED":
				alert_type = 'changes system/environment variables'
				reason = 'modifies system settings or environment variables'
				risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
				perms_needed.add('envvars')
			elif p == "SOURCE_ACCOUNT":
				alert_type = 'changes system/environment variables'
				reason = 'modifies system settings or environment variables'
				risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
				perms_needed.add('envvars')
			elif p == "SOURCE_USER_INPUT":
				alert_type = 'reads user input'
				reason = 'reads user input'
				risks = alert_user(alert_type, THREAT_MODEL, reason, risks)

			# report
			if reason not in report_data:
				report_data[reason] = usage
			else:
				report_data[reason] += usage

		print("ALERT [needs %d perms: %s]" % (len(perms_needed), ','.join(perms_needed)))
		report["permissions"] = report_data
	except Exception as e:
		print("FAILED [%s]" % (str(e)))
	finally:
		return risks, report

def main(pm_enum, pm_name, pkg_name):

	try:
		build_threat_model()
	except Exception as e:
		logging.debug("Failed to build threat model: %s!" % (str(e)))
		return

	pm_proxy = get_pm_proxy(pm_enum, cache_dir=None, isolate_pkg_info=False)
	assert pm_proxy, "%s not supported" % (pm_name)

	ver_str = None
	if '==' in pkg_name:
		pkg_name, ver_str = pkg_name.split('==')

	# get version metadata
	try:
		print("[+] Fetching '%s' from %s..." % (pkg_name, pm_name), end='', flush=True)
		pkg_info = pm_proxy.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
		assert pkg_info, "package not found!"

		#print(json.dumps(pkg_info, indent=4))
		try:
			pkg_name = pkg_info['info']['name']
		except KeyError:
			pass

		ver_info = pm_proxy.get_version(pkg_name, ver_str=ver_str, pkg_info=pkg_info)
		assert ver_info, "No version info!"

		#print(json.dumps(ver_info, indent=4))
		if not ver_str:
			ver_str = ver_info['tag']

		print("OK [ver %s]" % (ver_str))
	except Exception as e:
		print("FAILED [%s]" % (str(e)))
		exit(1)

	risks = {}
	report = {}

	# analyze metadata
	risks, report = analyze_pkg_descr(pm_proxy, pkg_name, ver_str, pkg_info, risks, report)
	risks, report = analyze_release_history(pm_proxy, pkg_name, pkg_info, risks, report)
	risks, report = analyze_version(ver_info, risks, report)
	risks, report = analyze_release_time(pm_proxy, pkg_name, ver_str, pkg_info, risks, report)
	risks, report = analyze_author(pm_proxy, pkg_name, ver_str, pkg_info, ver_info, risks, report)
	risks, report = analyze_readme(pm_proxy, pkg_name, ver_str, pkg_info, risks, report)
	risks, report = analyze_homepage(pm_proxy, pkg_name, ver_str, pkg_info, risks, report)
	risks, report = analyze_downloads(pm_proxy, pkg_name, risks, report)
	risks, report = analyze_repo_url(pm_proxy, pkg_name, ver_str, pkg_info, ver_info, risks, report)
	if 'repo' in report and 'url' in report['repo'] and report['repo']['url']:
		risks, report = analyze_repo_data(risks, report)
		if 'description' in report['repo']:
			risks, report = analyze_repo_descr(risks, report)
		risks, report = analyze_repo_activity(risks, report)
	risks, report = analyze_cves(pm_name, pkg_name, ver_str, risks, report)
	risks, report = analyze_deps(pm_proxy, pkg_name, ver_str, pkg_info, ver_info, risks, report)

	# download package
	try:
		print("[+] Downloading package '%s' (ver %s) from %s..." % (pkg_name, ver_str, pm_name), end='', flush=True)
		filepath, size = download_file(ver_info['url'])
		print("OK [%0.2f KB]" % (float(size)/1024))
	except KeyError:
		print("FAILED [URL missing]")
	except Exception as e:
		print("FAILED [%s]" % (str(e)))

	if filepath:
		risks, report = analyze_apis(pm_name, pkg_name, ver_str, filepath, risks, report)
		risks, report = analyze_composition(pm_name, pkg_name, ver_str, filepath, risks, report)

	print("=============================================")
	if not len(risks):
		print("[+] No risks found!")
		report["risks"] = None
	else:
		print("[+] %d risk(s) found, package is %s!" % (sum(len(v) for v in risks.values()), ', '.join(risks.keys())))
		report["risks"] = risks
	filename = "%s-%s-%s.json" % (pm_name, pkg_name, ver_str)
	write_json_to_file(filename, report, indent=4)
	print("=> Complete report: %s" % (filename))

	if pm_enum == PackageManagerEnum.pypi:
		print("=> View pre-vetted package report at https://packj.dev/package/PyPi/%s/%s" % (pkg_name, ver_str))

def get_base_pkg_info():
	from options import Options
	opts = Options(sys.argv[1:])
	assert opts, "Failed to parse cmdline args!"

	args = opts.args()
	assert args, "Failed to parse cmdline args!"

	if args.debug:
		import tempfile
		_, filename = tempfile.mkstemp(suffix='.log')
		print("*** Running in debug mode (log: %s) ***" % (filename))
		logging.basicConfig(filename=filename, datefmt='%H:%M:%S', level=logging.DEBUG,
							format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s')
	else:
		logging.getLogger().setLevel(logging.ERROR)

	pm_name = args.pm_name.lower()
	if pm_name == 'pypi':
		return PackageManagerEnum.pypi, pm_name, args.pkg_name
	if pm_name == 'npm':
		return PackageManagerEnum.npmjs, pm_name, args.pkg_name
	raise Exception("Package manager %s is not supported" % (pm_name))

if __name__ == "__main__":
	try:
		main(*get_base_pkg_info())
	except Exception as e_main:
		print(str(e_main))
		exit(1)
