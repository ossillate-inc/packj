#!/usr/bin/env python

from __future__ import print_function

from dataclasses import dataclass
from enum import Enum
import os
import logging
import yaml
import tempfile
from typing import Optional

from util.net import __parse_url, download_file, check_site_exist, check_domain_popular
from util.dates import datetime_delta
from util.email_validity import check_email_address
from util.files import write_json_to_file, read_from_csv
from util.enum_util import PackageManagerEnum, LanguageEnum
from util.formatting import human_format
from util.repo import git_clone, replace_last
from util.job_util import exec_command, in_docker, is_mounted

from parse_apis import parse_api_usage
from parse_composition import parse_package_composition
from pm_util import get_pm_enum, get_pm_install_cmd, get_pm_proxy
from static_util import get_static_proxy_for_language
from static_proxy.static_base import Language2Extensions
from parse_repo import fetch_repo_data
from parse_strace import parse_trace_file

THREAT_MODEL = {}

def msg_factory(fmt_str):
	def run(content):
		return fmt_str.format(content)
	return run

msg_fail = msg_factory('FAILED [{0}]')
msg_ok = msg_factory('OK [{0}]')
msg_alert = msg_factory('ALERT [{0}]')

def build_threat_model(filename='packj.yaml'):
	try:
		with open(filename) as f:
			config_data = yaml.safe_load(f)

		if 'audit' in config_data and 'alerts' in config_data['audit'] and config_data['audit']['alerts']:
			for category,category_data in config_data['audit']['alerts'].items():
				for sub_category, sub_data in category_data.items():
					for item in sub_data:
						if item.get('enabled', None) == True:
							THREAT_MODEL[sub_category] = category
							break
	except Exception as e:
		raise Exception(f'Failed to parse {filename}: {str(e)}')

	if len(THREAT_MODEL) == 0:
		raise Exception("No threat items in {filename} has been enabled")

def alert_user(alert_type, threat_model, reason, risks):
	if alert_type in threat_model:
		risk_cat = threat_model[alert_type]
		if risk_cat not in risks:
			risks[risk_cat] = []
		item = f'{alert_type}: {reason}'
		if item not in risks[risk_cat]:
			risks[risk_cat].append(item)
	return risks

def analyze_release_history(pm_proxy, pkg_name, pkg_info, risks, report, release_history=None):
	try:
		print('\t[+] Checking release history...', end='', flush=True)

		# get package release history
		if not release_history:
			release_history = pm_proxy.get_release_history(pkg_name, pkg_info=pkg_info)
			assert release_history, 'no data!'

		#import json
		#print(json.dumps(release_history, indent=4))

		if len(release_history) <= 2:
			reason = f'only {len(release_history)} versions released'
			alert_type = 'fewer versions or releases'
			risks = alert_user(alert_type, THREAT_MODEL, reason, risks)

		print(msg_ok(f'{len(release_history)} version(s)'))
		report['num_releases'] = len(release_history)
	except Exception as e:
		print(msg_fail(str(e)))
	finally:
		return risks, report, release_history

def analyze_release_time(pm_proxy, pkg_name, ver_str, pkg_info, risks, report, release_history=None):
	try:
		print('\t[+] Checking release time gap...', end='', flush=True)

		# get package release history
		if not release_history:
			release_history = pm_proxy.get_release_history(pkg_name, pkg_info=pkg_info)
			assert release_history, 'no data!'

		days = release_history[ver_str]['days_since_last_release']

		# check if the latest release is made after a long gap (indicative of package takeover)
		release_info = f'{days} days since last release' if days else 'first release'
		if days and days > 180:
			reason = f'version released after {days} days'
			alert_type = 'version release after a long gap'
			risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
			print(msg_alert(release_info))
		else:
			print(msg_ok(release_info))
	except Exception as e:
		print(msg_fail(str(e)))
	finally:
		return risks, report

def analyze_pkg_descr(pm_proxy, pkg_name, ver_str, pkg_info, risks, report):
	try:
		print('\t[+] Checking package description...', end='', flush=True)
		descr = pm_proxy.get_description(pkg_name, ver_str=ver_str, pkg_info=pkg_info)
		if not descr:
			reason = 'no description'
			alert_type = 'no description'
			risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
			print(msg_alert(reason))
		else:
			print(msg_ok(descr))
	except Exception as e:
		print(msg_fail(str(e)))
	finally:
		return risks, report

def analyze_version(ver_info, risks, report):
	try:
		print('[+] Checking version...', end='', flush=True)

		assert ver_info, 'no data!'

		# check upload timestamp
		try:
			uploaded = ver_info['uploaded']
			days = datetime_delta(uploaded, days=True)
		except KeyError:
			raise Exception('parse error')

		# check if the latest release is too old (unmaintained package)
		days_old = f'{days} days old'
		if not uploaded or days > 365:
			reason = 'no release date' if not uploaded else days_old
			alert_type = 'package is old or abandoned'
			risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
			print(msg_alert(days_old))
		else:
			print(msg_ok(days_old))
		report['version'] = ver_info
	except Exception as e:
		print(msg_fail(str(e)))
	finally:
		return risks, report

def analyze_cves(pm_name, pkg_name, ver_str, risks, report):
	try:
		print('[+] Checking for CVEs...', end='', flush=True)
		from osv import get_pkgver_vulns
		vuln_list = get_pkgver_vulns(pm_name, pkg_name, ver_str)
		if vuln_list:
			alert_type = 'contains known vulnerabilities (CVEs)'
			vulnerabilities = ','.join(vul['id'] for vul in vuln_list)
			reason = f'contains {vulnerabilities}'
			risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
			print(msg_alert(f'{len(vuln_list)} found'))
		else:
			vuln_list = []
			print(msg_ok('none found'))
		report['vulnerabilities'] = vuln_list
	except Exception as e:
		print(msg_fail(str(e)))
	finally:
		return risks, report

def analyze_deps(pm_proxy, pkg_name, ver_str, pkg_info, ver_info, risks, report):
	try:
		print('[+] Checking dependencies...', end='', flush=True)
		deps = pm_proxy.get_dependencies(pkg_name, ver_str=ver_str, pkg_info=pkg_info, ver_info=ver_info)
		if deps and len(deps) > 10:
			alert_type = 'too many dependencies'
			reason = f'{len(deps)} found'
			risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
			print(msg_alert(reason))
		else:
			print(msg_ok(f'{len(deps)} direct' if deps else 'none found'))
	except Exception as e:
		print(msg_fail(str(e)))
	finally:
		return risks, report

def analyze_downloads(pm_proxy, pkg_name, pkg_info, risks, report):
	try:
		print('[+] Checking downloads...', end='', flush=True)
		ret = pm_proxy.get_downloads(pkg_name, pkg_info)
		assert ret != None, "N/A"
		if ret < 1000:
			reason = f'only {ret} weekly downloads'
			alert_type = 'fewer downloads'
			risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
		print(msg_ok(f'{human_format(ret)} weekly'))
	except Exception as e:
		print(msg_fail(str(e)))
	finally:
		return risks, report

def analyze_homepage(pm_proxy, pkg_name, ver_str, pkg_info, risks, report):
	try:
		print('[+] Checking homepage...', end='', flush=True)
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
		print(msg_ok(url))
		report['homepage'] = url
	except Exception as e:
		print(msg_fail(str(e)))
	finally:
		return risks, report

def analyze_repo_descr(risks, report):
	try:
		print('\t[+] Checking repo description...', end='', flush=True)
		descr = report['repo']['description']
		print(msg_ok(descr))
	except Exception as e:
		print(msg_fail(str(e)))
	finally:
		return risks, report

def analyze_repo_data(risks, report):
	try:
		repo_url = report['repo']['url']
		print('\t[+] Checking repo data...', end='', flush=True)
		err, repo_data	= fetch_repo_data(repo_url)
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
			reason = f'only {num_forks} forks'
			risks = alert_user(alert_type, THREAT_MODEL, reason, risks)

		if num_stars and num_stars < 10:
			alert_type = 'few source repo stars'
			reason = f'only {num_stars} stars'
			risks = alert_user(alert_type, THREAT_MODEL, reason, risks)

		print(msg_ok(f'stars: {num_stars}, forks: {num_forks}'))
		report['repo'].update(repo_data)
	except Exception as e:
		print(msg_fail(str(e)))

	if not repo_data:
		return risks, report

	try:
		print('\t[+] Checking if repo is a forked copy...', end='', flush=True)
		if forked_from:
			alert_type = 'source repo is a forked copy'
			reason = f'forked from {forked_from}'
			risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
			print(msg_alert(reason))
		else:
			print(msg_ok('original, not forked'))
	except Exception as e:
		print(msg_fail(str(e)))
	finally:
		return risks, report

def analyze_repo_activity(risks, report):
	try:
		repo_url = report['repo']['url']
		print('\t[+] Checking repo activity...', end='', flush=True)
		reason, repo_data = git_clone(repo_url)
		if reason:
			alert_type = 'invalid or no source repo'
			risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
			print(msg_alert(reason))
		elif repo_data:
			commits, contributors, tags = tuple(repo_data[k] for k in ('commits', 'contributors', 'tags'))
			print(msg_ok(f'commits: {commits}, contributors: {contributors}, tags: {tags}'))
			report['repo'].update(repo_data)
	except Exception as e:
		print(msg_fail(str(e)))
	finally:
		return risks, report

def analyze_repo_url(pm_proxy, pkg_name, ver_str, pkg_info, ver_info, risks, report):
	try:
		print('[+] Checking repo URL...', end='', flush=True)
		popular_hosting_services = (
			'https://github.com/',
			'https://gitlab.com/',
			'git+https://github.com/',
			'git://github.com/',
			'https://bitbucket.com/',
		)
		repo_url = pm_proxy.get_repo(pkg_name, ver_str=ver_str, pkg_info=pkg_info, ver_info=ver_info)
		if not repo_url:
			repo_url = pm_proxy.get_homepage(pkg_name, ver_str=ver_str, pkg_info=pkg_info)
			if not repo_url or not repo_url.startswith(popular_hosting_services):
				repo_url = None
		if not repo_url:
			repo_url = pm_proxy.get_download_url(pkg_name, ver_str=ver_str, pkg_info=pkg_info)
			if not repo_url or not repo_url.startswith(popular_hosting_services):
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
		elif not repo_url.startswith(popular_hosting_services):
			reason = f'invalid source repo {repo_url}'
			alert_type = 'invalid or no source repo'
			risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
		print(msg_ok(repo_url))
		report['repo'] = {
			'url' : repo_url,
		}
	except Exception as e:
		print(msg_fail(str(e)))
	finally:
		return risks, report

def analyze_readme(pm_proxy, pkg_name, ver_str, pkg_info, risks, report):
	try:
		print('[+] Checking readme...', end='', flush=True)
		readme = pm_proxy.get_readme(pkg_name, ver_str=ver_str, pkg_info=pkg_info)
		if not readme or len(readme) < 100:
			reason = 'no readme' if not readme else 'insufficient readme'
			alert_type = 'no or insufficient readme'
			risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
			print(msg_alert(reason))
		else:
			print(msg_ok(f'{len(readme)} bytes'))
	except Exception as e:
		print(msg_fail(str(e)))
	finally:
		return risks, report

def analyze_author(pm_proxy, pkg_name, ver_str, pkg_info, ver_info, risks, report):
	try:
		print('[+] Checking author...', end='', flush=True)

		# check author/maintainer email
		authors = pm_proxy.get_author(pkg_name, ver_str=ver_str, pkg_info=pkg_info, ver_info=ver_info)
		assert authors, 'no data!'
		assert isinstance(authors, list), "invalid format!"

		# format as a list of emails/names
		item_list = []
		for dev in authors:
			item = dev.get('email', None)
			if not item:
				item = dev.get('handle', None)
			if not item:
				item = dev.get('name', None)
			if item:
				item_list.append(item)
		data = ','.join(item_list)

		report['authors'] = authors
		print(msg_ok(data))
	except Exception as e:
		print(msg_fail(str(e)))
		return risks, report

	try:
		print('\t[+] Checking email/domain validity...', end='', flush=True)
		for author_info in authors:
			email = author_info.get('email', None)
			if not email:
				break
			try:
				valid, valid_with_dns = check_email_address(email)
			except Exception as e:
				logging.debug('Failed to parse email %s: %s' % (email, str(e)))
				valid = False
			if not valid or not valid_with_dns:
				break

		def get_alert_reason():
			if not email:
				# Rubygems allow devs to hide their emails
				if pm_proxy.name == 'rubygems':
					return 'no email (may be hidden)', False
				else:
					return 'no email', True
			if not valid:
				return 'invalid author email', True
			if not valid_with_dns:
				return 'expired author email domain', True
			return None, True

		reason, must_alert = get_alert_reason()
		if reason:
			if must_alert:
				alert_type = 'invalid or no author email'
				risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
			print(msg_alert(reason))
		else:
			print(msg_ok(email))
	except Exception as e:
		print(msg_fail(str(e)))
	finally:
		return risks, report

def analyze_composition(pm_name, pkg_name, ver_str, filepath, risks, report):
	try:
		print('[+] Checking files/funcs...', end='', flush=True)

		if pm_name == 'pypi':
			language=LanguageEnum.python
		elif pm_name == 'npm':
			language=LanguageEnum.javascript
		elif pm_name == 'rubygems':
			language=LanguageEnum.ruby
		else:
			raise Exception(f'Package manager {pm_name} is not supported!')

		num_files, lang_files, num_funcs, total_loc = parse_package_composition(
			pkg_name,
			ver_str,
			filepath + '.out.json',
		)
		lang_file_ext = ','.join(Language2Extensions[language])

		content = (
			f'{num_files} files ({lang_files} {lang_file_ext}), '
			f'{num_funcs} funcs, '
			f'LoC: {human_format(total_loc)}'
		)
		print(msg_ok(content))
		report['composition'] = {
			'num_files' : num_files,
			'num_funcs' : num_funcs,
			f'{lang_file_ext}_files': lang_files,
			'Loc'		: total_loc,
		}
	except Exception as e:
		print(msg_fail(str(e)))
	finally:
		return risks, report


class Risk(tuple, Enum):
	FILE_IO = 'accesses files and dirs', 'file'
	USER_IO = 'reads user input', None	# should this really be None?
	NET = 'communicates with external network', 'network'
	CODE = 'generates new code at runtime', 'codegen'
	PROC = 'forks or exits OS processes', 'process'
	HIDDEN = 'accesses obfuscated (hidden) code', 'decode'
	ENV_READ = 'accesses system/environment variables', 'envvars'
	ENV_WRITE = 'changes system/environment variables', 'envvars'

@dataclass
class Alert:
	risk: Risk
	desc: Optional[str] = None


ALERTS = {
	'SOURCE_FILE': Alert(Risk.FILE_IO, 'reads files and dirs'),
	'SINK_FILE': Alert(Risk.FILE_IO, 'writes to files and dirs'),
	'SINK_NETWORK': Alert(Risk.NET, 'sends data over the network'),
	'SOURCE_NETWORK': Alert(Risk.NET, 'fetches data over the network'),
	'SINK_CODE_GENERATION': Alert(Risk.CODE),
	'SINK_PROCESS_OPERATION': Alert(Risk.PROC, 'performs a process operation'),
	'SOURCE_OBFUSCATION': Alert(Risk.HIDDEN, 'reads hidden code'),
	'SOURCE_SETTINGS': Alert(Risk.ENV_READ, 'reads system settings or environment variables'),
	'SINK_UNCLASSIFIED': Alert(Risk.ENV_WRITE, 'modifies system settings or environment variables'),
	'SOURCE_ACCOUNT': Alert(Risk.ENV_WRITE, 'modifies system settings or environment variables'),
	'SOURCE_USER_INPUT': Alert(Risk.USER_IO),
}

def analyze_apis(pm_name, pkg_name, ver_str, filepath, risks, report):
	try:
		print('[+] Analyzing code...', end='', flush=True)
		if pm_name == 'pypi':
			language=LanguageEnum.python
			configpath = os.path.join('config','astgen_python_smt.config')
			system = 'python2'
		elif pm_name == 'npm':
			language=LanguageEnum.javascript
			configpath = os.path.join('config','astgen_javascript_smt.config')
			system = 'python'
		elif pm_name == 'rubygems':
			language=LanguageEnum.ruby
			configpath = os.path.join('config','astgen_ruby_smt.config')
			system = 'ruby'
		else:
			raise Exception(f'Package manager {pm_name} is not supported!')

		static = get_static_proxy_for_language(language=language)
		try:
			static.astgen(inpath=filepath, outfile=filepath+'.out', root=None, configpath=configpath,
				pkg_name=pkg_name, pkg_version=ver_str, evaluate_smt=False)
		except Exception as e:
			logging.debug('Failed to parse: %s', str(e))
			raise Exception('parse error: is %s installed?' % (system))

		assert os.path.exists(filepath+'.out'), 'parse error!'

		perms = parse_api_usage(pm_name, filepath+'.out')
		if not perms:
			print(msg_ok('no perms found'))
			return risks, report

		report_data = {}
		perms_needed = set()
		for p, usage in perms.items():
			alert = ALERTS[p]
			alert_type, needs_perm = alert.risk
			reason = alert.desc or alert_type

			risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
			if needs_perm:
				perms_needed.add(needs_perm)

			# report
			if reason not in report_data:
				report_data[reason] = usage
			else:
				report_data[reason] += usage

		print(msg_alert(f'needs {len(perms_needed)} perm(s): {",".join(perms_needed)}'))
		report['permissions'] = report_data
	except Exception as e:
		print(msg_fail(str(e)))
	finally:
		return risks, report

def trace_installation(pm_enum, pkg_name, ver_str, report_dir, risks, report):
	try:
		print('[+] Installing package and tracing code...', end='', flush=True)

		# look for strace binary
		check_strace_cmd = ['which', 'strace']
		stdout, stderr, error = exec_command("strace", check_strace_cmd, redirect_mask=3)
		if error:
			logging.debug(f'strace binary not found:\n{stdout}\n{stderr}')
			raise Exception(f'strace missing!')

		# check that we collected the correct binary path
		strace_bin = stdout
		if strace_bin == '':
			raise Exception('"strace" not installed!')
		if not os.path.exists(strace_bin):
			raise Exception(f'{strace_bin} not found!')

		# install package under strace and collect system call traces
		install_cmd = get_pm_install_cmd(pm_enum, pkg_name, ver_str)
		_, trace_filepath = tempfile.mkstemp(prefix='trace_', dir=report_dir, suffix='.log')

		strace_cmd = f'{strace_bin} -f -e trace=network,file,process -ttt -T -o {trace_filepath } {install_cmd}'
		stdout, stderr, error = exec_command("strace", strace_cmd.split(), redirect_mask=3)
		if error:
			logging.debug(f'strace failed with:\n{stdout}\n{stderr}')
			raise Exception(f'code {error}')

		# check if the trace file is generated
		if not os.path.exists(trace_filepath):
			raise Exception('no trace generated!')

		summary = parse_trace_file(trace_filepath, report_dir)
		assert summary, "parse error!"

		# consolidate
		out = ','.join([f'{len(summary[k])} {k}' for k in summary.keys()])
		print(msg_ok(f'found {out} syscalls'))
	except Exception as e:
		print(msg_fail(str(e)))
	finally:
		return risks, report

def audit(pm_enum, pm_name, pkg_name, ver_str, report_dir, extra_args):

	host_volume, container_mountpoint, install_trace = extra_args

	pm_proxy = get_pm_proxy(pm_enum, cache_dir=None, isolate_pkg_info=False)

	# get version metadata
	try:
		print(f"[+] Fetching '{pkg_name}' from {pm_name}...", end='', flush=True)
		pkg_name, pkg_info = pm_proxy.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
		assert pkg_info, 'package not found!'

		ver_info = pm_proxy.get_version(pkg_name, ver_str=ver_str, pkg_info=pkg_info)
		assert ver_info, 'No version info!'

		if not ver_str:
			ver_str = ver_info['tag']

		print(msg_ok(f'ver {ver_str}'))
	except Exception as e:
		print(msg_fail(str(e)))
		exit(1)

	risks = {}
	report = {}

	# analyze metadata
	risks, report = analyze_pkg_descr(pm_proxy, pkg_name, ver_str, pkg_info, risks, report)
	risks, report, release_history = analyze_release_history(pm_proxy, pkg_name, pkg_info, risks, report)
	risks, report = analyze_version(ver_info, risks, report)
	risks, report = analyze_release_time(pm_proxy, pkg_name, ver_str, pkg_info, risks, report, release_history)
	risks, report = analyze_author(pm_proxy, pkg_name, ver_str, pkg_info, ver_info, risks, report)
	risks, report = analyze_readme(pm_proxy, pkg_name, ver_str, pkg_info, risks, report)
	risks, report = analyze_homepage(pm_proxy, pkg_name, ver_str, pkg_info, risks, report)
	risks, report = analyze_downloads(pm_proxy, pkg_name, pkg_info, risks, report)
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
		print(
			f"[+] Downloading package '{pkg_name}' (ver {ver_str}) from {pm_name}...",
			end='',
			flush=True
		)
		filepath, size = download_file(ver_info['url'])
		print(msg_ok(f'{float(size)/1024:.2f} KB'))
	except KeyError:
		print(msg_fail('URL missing'))
	except Exception as e:
		print(msg_fail(str(e)))

	# perform static analysis
	if filepath:
		risks, report = analyze_apis(pm_name, pkg_name, ver_str, filepath, risks, report)
		risks, report = analyze_composition(pm_name, pkg_name, ver_str, filepath, risks, report)

	# perform dynamic analysis if requested
	if install_trace:
		risks, report = trace_installation(pm_enum, pkg_name, ver_str, report_dir, risks, report)

	print('=============================================')

	# aggregate risks
	if not risks:
		print('[+] No risks found!')
		report['risks'] = None
	else:
		print(
			f'[+] {sum(len(v) for v in risks.values())} risk(s) found, '
			f'package is {", ".join(risks.keys())}!'
		)
		report['risks'] = risks

	# generate final report
	_, filepath = tempfile.mkstemp(prefix=f'report_', dir=report_dir, suffix='.json')
	write_json_to_file(filepath, report, indent=4)
	os.chmod(filepath, 0o444)
	if not container_mountpoint:
		print(f'=> Complete report: {filepath}')
	else:
		report_path = filepath.replace(container_mountpoint, host_volume)
		print(f'=> Complete report: {report_path}')

	# report link
	if pm_enum == PackageManagerEnum.pypi:
		print(f'=> View pre-vetted package report at https://packj.dev/package/PyPi/{pkg_name}/{ver_str}')

def get_report_dir_suffix(pm_name, pkg_name, ver_str):
	if not ver_str:
		logging.debug(f'No version specified. Using latest version of {pkg_name}')
		ver_str = 'latest'
	if pkg_name.startswith('@'):
		pkg_name = pkg_name.lstrip('@').replace('/', '-')
	return f'_{pm_name}_{pkg_name}_{ver_str}'

def parse_request_args(args):
	install_trace = False
	host_volume = None
	container_mountpoint = None

	# XXX expects host volume to be mounted inside container
	if in_docker():
		container_mountpoint = '/tmp/packj'
		host_volume = is_mounted(container_mountpoint)
		if not host_volume or not os.path.exists(container_mountpoint):
			print(f'Missing host volume at {container_mountpoint}. Run Docker with "-v /tmp:{container_mountpoint}" argument.')
			exit(1)

	# pm enum ID
	pm_name = args.pm_name.lower()
	pm_enum = get_pm_enum(pm_name)

	# create a temp dir to host debug logs, trace logs, and final report
	try:
		report_dir_suffix = get_report_dir_suffix(pm_name, args.pkg_name, args.ver_str)
		report_dir = tempfile.mkdtemp(prefix=f'packj_', dir=container_mountpoint, suffix=report_dir_suffix)
		os.chmod(report_dir, 0o755)
	except Exception as e:
		print(f'Failed to create temp dir: {str(e)}!')
		exit(1)

	# enable debugging if requested
	if args.debug:
		try:
			_, filename = tempfile.mkstemp(prefix='debug_', dir=report_dir, suffix='.log')
			os.chmod(filename, 0o544)
			print(f'\n*** NOTE: Running in debug mode (log: {filename}) ***\n')
			logging.basicConfig(filename=filename, datefmt='%H:%M:%S', level=logging.DEBUG,
								format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s')
		except Exception as e:
			print(f'Failed to create debug log: {str(e)}. Using stdout.')
			logging.getLogger().setLevel(logging.DEBUG)
	else:
		logging.getLogger().setLevel(logging.ERROR)

	# check if installation trace has been requested
	if args.trace:
		if not in_docker():
			print(f'*** You\'ve requested package installation trace *** We recommend running in Docker. Continue (N/y): ', end='')
			stop = input()
			if stop != 'y':
				exit(0)
		install_trace = True

	return (pm_enum, pm_name, args.pkg_name, args.ver_str), report_dir, (host_volume, container_mountpoint, install_trace)

def main(args):

	# get user threat model
	build_threat_model()

	# collect package info
	pkg_info, report_dir, cmd_args = parse_request_args(args)
	audit(*pkg_info, report_dir, cmd_args)
