#!/usr/bin/env python

from dataclasses import dataclass
from enum import Enum
import os
import inspect
import logging
import yaml
import tempfile
from typing import Optional
import email.utils as eutils

from colorama import Fore, Style

from packj.util.net import __parse_url, download_file, check_site_exist, check_domain_popular
from packj.util.dates import datetime_delta
from packj.util.email_validity import check_email_address
from packj.util.files import write_json_to_file, read_from_csv, read_file_lines
from packj.util.enum_util import PackageManagerEnum, LanguageEnum
from packj.util.formatting import human_format
from packj.util.repo import git_clone, replace_last
from packj.util.job_util import exec_command, in_docker, in_podman, is_mounted

from packj.audit.parse_apis import parse_api_usage
from packj.audit.parse_composition import parse_package_composition
from packj.audit.pm_util import get_pm_enum, get_pm_install_cmd, get_pm_proxy
from packj.audit.static_util import get_static_proxy_for_language
from packj.audit.static_proxy.static_base import Language2Extensions
from packj.audit.parse_repo import fetch_repo_data
from packj.audit.parse_strace import parse_trace_file
from packj.audit.report import generate_package_report, generate_summary

THREAT_MODEL = {}

def msg_info(x, end='\n', flush=True, indent=0):
	while indent > 0:
		x = '   ' + x
		indent -= 1
	if end != '\n':
		while len(x) < 40:
			x += '.'
		print(f'{Style.BRIGHT}[+]{Style.RESET_ALL} {x}', end=end, flush=flush)
	else:
		print(x, end=end, flush=flush)
def msg_ok(x):
	if len(x) > 50:
		x = ''.join(x[0:46]) + ' ...'
	msg_info(f'{Style.BRIGHT}{Fore.GREEN}PASS{Style.RESET_ALL} [{Fore.BLUE}{x}{Style.RESET_ALL}]')
def msg_fail(x):
	msg_info(f'{Style.BRIGHT}{Fore.YELLOW}FAIL{Style.RESET_ALL} [{x}]')
def msg_alert(x):
	msg_info(f'{Style.BRIGHT}{Fore.RED}RISK{Style.RESET_ALL} [{x}]')
def msg_warn(tag, x):
	msg_info(f'{Style.BRIGHT}{Fore.YELLOW}{tag}{Style.RESET_ALL} [{Fore.MAGENTA}{x}{Style.RESET_ALL}]')

def build_threat_model(filename):
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

	return config_data

def alert_user(alert_type, threat_model, reason, risks):
	if alert_type in threat_model:
		risk_cat = threat_model[alert_type]
		if risk_cat not in risks:
			risks[risk_cat] = []
		item = f'{alert_type}: {reason}'
		if item not in risks[risk_cat]:
			risks[risk_cat].append(item)
	return risks

def analyze_yanked_releases(pm_proxy, pkg_name, pkg_info, risks, report, release_history):
	try:
		msg_info('Checking for yanked releases...', end='', flush=True, indent=2)

		if pm_proxy.name == 'rubygems' or pm_proxy.name == 'packagist':
			msg_warn(' N/A','Not supported!')
			return risks, report

		num_releases = len(release_history)
		num_yanked = sum([v['yanked'] for v in release_history.values()])

		if (num_releases == num_yanked) or (num_releases > 3 and num_yanked > int(num_releases/2)):
			reason = f'more than 50% ({num_yanked}) of {num_releases} releases were yanked'
			alert_type = 'high release-yank ratio'
			risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
			release_yanked_info = f'{num_yanked} version(s) were yanked'
			msg_alert(release_yanked_info)
		else:
			msg_ok('No versions were yanked')
	except Exception as e:
		msg_fail(str(e))
	finally:
		return risks, report

def analyze_release_history(pm_proxy, pkg_name, pkg_info, risks, report, release_history=None):
	try:
		msg_info('Checking release history...', end='', flush=True, indent=1)

		# get package release history
		if not release_history:
			release_history = pm_proxy.get_release_history(pkg_name, pkg_info=pkg_info)
			assert release_history, 'no data!'

		#import json
		#msg_info(json.dumps(release_history, indent=4))

		if len(release_history) <= 2:
			reason = f'only {len(release_history)} versions released'
			alert_type = 'fewer versions or releases'
			risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
			msg_alert(reason)
		else:
			msg_ok(f'{len(release_history)} version(s)')
		report['num_releases'] = len(release_history)
	except Exception as e:
		msg_fail(str(e))
	finally:
		return risks, report, release_history

def analyze_release_time(pm_proxy, pkg_name, ver_str, pkg_info, risks, report, release_history=None):
	try:
		msg_info('Checking release time gap...', end='', flush=True, indent=1)

		# get package release history
		if not release_history:
			release_history = pm_proxy.get_release_history(pkg_name, pkg_info=pkg_info)
			assert release_history, 'no data!'

		days = release_history[ver_str]['days_since_last_release']

		# check if the release is made after a long gap (indicative of package takeover)
		release_info = f'{days} days since last release' if days else 'first release'
		if days and days > 180:
			reason = f'version released after {days} days'
			alert_type = 'version release after a long gap'
			risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
			msg_alert(release_info)
		else:
			msg_ok(release_info)
	except Exception as e:
		msg_fail(str(e))
	finally:
		return risks, report

def analyze_pkg_descr(pm_proxy, pkg_name, ver_str, pkg_info, risks, report):
	try:
		msg_info('Checking package description...', end='', flush=True, indent=1)
		descr = pm_proxy.get_description(pkg_name, ver_str=ver_str, pkg_info=pkg_info)
		if not descr:
			reason = 'no description'
			alert_type = 'no description'
			risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
			msg_alert(reason)
		else:
			msg_ok(descr)
		report['description'] = descr
	except Exception as e:
		msg_fail(str(e))
	finally:
		return risks, report

def analyze_version(pm_proxy, pkg_name, ver_info, risks, report):
	try:
		msg_info('Checking version...', end='', flush=True)

		assert ver_info, 'No version info!'
		requested_ver_str = ver_info['tag']

		# fetch the latest package metadata
		latest_ver_info = pm_proxy.get_version(pkg_name, ver_str=None, pkg_info=None)
		assert latest_ver_info, 'No latest version info!'

		latest_ver_str = latest_ver_info['tag']
		if latest_ver_str != requested_ver_str:
			msg_warn('WARN', 'not latest')
		else:
			msg_ok('Latest release')
		report['version'] = ver_info
	except Exception as e:
		msg_fail(str(e))
		return risks, report

	try:
		msg_info('Checking if old/abandoned...', end='', flush=True, indent=1)

		# check upload timestamp
		try:
			uploaded = ver_info['uploaded']
			days = datetime_delta(uploaded, days=True)
		except KeyError:
			raise Exception('uploaded time data missing')

		# check if the release is too old (unmaintained package)
		days_old = f'{days} days old'
		if not uploaded or days > 365:
			reason = 'no release date' if not uploaded else days_old
			alert_type = 'package is old or abandoned'
			risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
			msg_alert(days_old)
		else:
			msg_ok(days_old)
	except Exception as e:
		msg_fail(str(e))
	finally:
		return risks, report

def analyze_cves(pm_name, pkg_name, ver_str, risks, report):
	try:
		msg_info('Checking for CVEs...', end='', flush=True)
		from packj.audit.osv import get_pkgver_vulns
		vuln_list = get_pkgver_vulns(pm_name, pkg_name, ver_str)
		if vuln_list:
			alert_type = 'contains known vulnerabilities'
			vulnerabilities = ','.join(vul['id'] for vul in vuln_list)
			reason = f'contains {vulnerabilities}'
			risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
			msg_alert(f'{len(vuln_list)} found')
		else:
			vuln_list = []
			msg_ok('none found')
		report['vulnerabilities'] = vuln_list
	except Exception as e:
		msg_fail(str(e))
	finally:
		return risks, report

def analyze_deps(pm_proxy, pkg_name, ver_str, pkg_info, ver_info, risks, report):
	try:
		msg_info('Checking dependencies...', end='', flush=True)
		deps = pm_proxy.get_dependencies(pkg_name, ver_str=ver_str, pkg_info=pkg_info, ver_info=ver_info)
		if deps and len(deps) > 10:
			alert_type = 'too many dependencies'
			reason = f'{len(deps)} found'
			risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
			msg_alert(reason)
		else:
			msg_ok(f'{len(deps)} direct' if deps else 'none found')
		report['dependencies'] = deps
	except Exception as e:
		report['dependencies'] = ' N/A'
		msg_fail(str(e))
	finally:
		return risks, report

def analyze_zero_width_unicode(pm_proxy, pkg_name, pkg_info, risks, report):

	# List of malicious symbols
	symbols = [u'\u200b', u'\u200c', u'\u200d', u'\u200e', u'\u200f', #U+200x
				u'\u202a', u'\u202b', u'\u202c', u'\u202d', #U+202x
				u'\u2060', u'\u2061', u'\u2062', u'\u2063', u'\u2064',
				u'\u2065', u'\u2066', u'\u2067', u'\u2068', u'\u2069',
				u'\u206a', u'\u206b', u'\u206c', u'\u206d', u'\u206e' #U+206x
			]
	try:
		msg_info('Checking for zero-width unicode chars...', end='', flush=True)
		# TODO
		msg_warn(' N/A','Coming soon!')
	except Exception as e:
		msg_fail(str(e))
	finally:
		return risks, report

def analyze_install_hooks(pm_proxy, pkg_name, pkg_info, risks, report):
	try:
		msg_info('Checking for install-time hooks...', end='', flush=True)
		# TODO
		msg_warn(' N/A','Coming soon!')
	except Exception as e:
		msg_fail(str(e))
	finally:
		return risks, report

def analyze_typosquatting(pm_proxy, pkg_name, pkg_info, risks, report):
	try:
		msg_info('Checking for typo-squatting...', end='', flush=True)
		# TODO
		msg_warn(' N/A','Coming soon!')
	except Exception as e:
		msg_fail(str(e))
	finally:
		return risks, report

def analyze_dep_confusion(pm_proxy, pkg_name, pkg_info, risks, report):
	try:
		msg_info('Checking for dependency confusion...', end='', flush=True)
		# TODO
		msg_warn(' N/A','Coming soon!')
	except Exception as e:
		msg_fail(str(e))
	finally:
		return risks, report

def analyze_downloads(pm_proxy, pkg_name, pkg_info, risks, report):
	try:
		msg_info('Checking downloads...', end='', flush=True)
		ret = pm_proxy.get_downloads(pkg_name, pkg_info)
		assert ret != None, " N/A"
		if ret < 1000:
			reason = f'only {ret} weekly downloads'
			alert_type = 'fewer downloads'
			risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
			msg_alert(reason)
		else:
			msg_ok(f'{human_format(ret)} weekly')
		report['downloads'] = f'{human_format(ret)} weekly'
	except Exception as e:
		logging.debug(f'Failed to get downloads for {pm_proxy} {pkg_name}: {str(e)}')
		msg_fail('Not available')
	finally:
		return risks, report

def analyze_homepage(pm_proxy, pkg_name, ver_str, pkg_info, risks, report):
	try:
		msg_info('Checking homepage...', end='', flush=True)
		url = pm_proxy.get_homepage(pkg_name, ver_str=ver_str, pkg_info=pkg_info)
		if not url:
			reason = 'no homepage'
			alert_type = 'invalid or no homepage'
			risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
			msg_alert(reason)
		else:
			# check if insecure
			ret = __parse_url(url)
			if ret.scheme == 'https':
				valid_site = check_site_exist(url)

			if ret.scheme != 'https':
				reason = 'insecure webpage'
				alert_type = 'invalid or no homepage'
				risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
				msg_alert(reason)

			# check if an existent webpage
			elif not valid_site:
				reason = 'nonexistent webpage'
				alert_type = 'invalid or no homepage'
				risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
				msg_alert(reason)

			# check if a popular webpage
			elif check_domain_popular(url):
				reason = 'invalid (popular) webpage'
				alert_type = 'invalid or no homepage'
				risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
				msg_alert(reason)

			else:
				msg_ok(url)
		report['homepage'] = url
	except Exception as e:
		msg_fail(str(e))
	finally:
		return risks, report

def analyze_repo_descr(risks, report):
	try:
		msg_info('Checking repo description...', end='', flush=True, indent=1)
		descr = report['repo']['description']
		msg_ok(descr)
	except Exception as e:
		msg_fail(str(e))
	finally:
		return risks, report

def analyze_repo_data(config, risks, report):
	try:
		repo_url = report['repo']['url']
		msg_info('Checking repo data...', end='', flush=True, indent=1)
		err, repo_data	= fetch_repo_data(config, repo_url)
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

		msg = ''
		alert = False
		if num_forks and num_forks < 5:
			alert_type = 'few source repo forks'
			reason = f'only {num_forks} forks'
			risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
			msg += reason
			alert = True
		else:
			msg += f'forks: {num_forks}'

		msg += ', '
		if num_stars and num_stars < 10:
			alert_type = 'few source repo stars'
			reason = f'only {num_stars} stars'
			risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
			msg += reason
			alert = True
		else:
			msg += f'stars: {num_stars}'

		if alert:
			msg_alert(msg)
		else:
			msg_ok(msg)

		report['repo'].update(repo_data)
	except Exception as e:
		msg_fail(str(e))

	if not repo_data:
		return risks, report

	try:
		msg_info('Checking if repo is a forked copy...', end='', flush=True, indent=1)
		if forked_from:
			alert_type = 'source repo is a forked copy'
			reason = f'forked from {forked_from}'
			risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
			msg_alert(reason)
		else:
			msg_ok('original, not forked')
	except Exception as e:
		msg_fail(str(e))
	finally:
		return risks, report

def analyze_repo_activity(risks, report):
	try:
		repo_url = report['repo']['url']
		msg_info('Checking repo activity...', end='', flush=True, indent=1)
		reason, repo_data = git_clone(repo_url)
		if reason:
			alert_type = 'invalid or no source repo'
			risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
			msg_alert(reason)
		elif repo_data:
			commits, contributors, tags = tuple(repo_data[k] for k in ('commits', 'contributors', 'tags'))
			msg_ok(f'commits: {commits}, contributors: {contributors}, tags: {tags}')
		report['repo'].update(repo_data)
	except Exception as e:
		msg_fail(str(e))
	finally:
		return risks, report

def analyze_repo_code(risks, report):
	try:
		repo_url = report['repo']['url']
		msg_info('Analyzing repo-pkg src code match...', end='', flush=True, indent=1)
		# TODO
		msg_warn(' N/A','Coming soon!')
	except Exception as e:
		msg_fail(str(e))
	finally:
		return risks, report

def analyze_repo_url(pm_proxy, pkg_name, ver_str, pkg_info, ver_info, risks, report):
	try:
		msg_info('Checking repo URL...', end='', flush=True)
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
			if len(repo_url) == 0:
				repo_url = None
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
			msg_alert(reason)
		elif not repo_url.startswith(popular_hosting_services):
			reason = f'invalid source repo {repo_url}'
			alert_type = 'invalid or no source repo'
			risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
			msg_alert(reason)
		else:
			msg_ok(repo_url)
		report['repo'] = {
			'url' : repo_url,
		}
	except Exception as e:
		msg_fail(str(e))
	finally:
		return risks, report

def analyze_readme(pm_proxy, pkg_name, ver_str, pkg_info, risks, report):
	try:
		msg_info('Checking readme...', end='', flush=True)
		readme = pm_proxy.get_readme(pkg_name, ver_str=ver_str, pkg_info=pkg_info)
		if pm_proxy.name == 'packagist':
			msg_warn(' N/A','Not supported!')
			return risks, report
		if not readme or len(readme) < 100:
			reason = 'no readme' if not readme else 'insufficient readme'
			alert_type = 'no or insufficient readme'
			risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
			msg_alert(reason)
		else:
			msg_ok(f'{len(readme)} bytes')
	except Exception as e:
		msg_fail(str(e))
	finally:
		return risks, report

def analyze_author(pm_proxy, pkg_name, ver_str, pkg_info, ver_info, risks, report):
	try:
		msg_info('Checking author...', end='', flush=True)

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
		msg_ok(data)
	except Exception as e:
		msg_fail(str(e))
		return risks, report

	try:
		msg_info('Checking email/domain validity...', end='', flush=True, indent=1)
		for author_info in authors:
			email = author_info.get('email', None)
			if not email:
				break
			try:
				_,email = eutils.getaddresses([email])[0]
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
					return 'no email (may be hidden)', True
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
			msg_alert(reason)
		else:
			msg_ok(email)
	except Exception as e:
		msg_fail(str(e))
	finally:
		return risks, report

def analyze_composition(pm_name, pkg_name, ver_str, filepath, risks, report):
	try:
		msg_info('Checking files/funcs...', end='', flush=True)

		if pm_name == 'pypi' or pm_name == 'local_python':
			language=LanguageEnum.python
		elif pm_name == 'npm' or pm_name == 'local_nodejs':
			language=LanguageEnum.javascript
		elif pm_name == 'rubygems':
			language=LanguageEnum.ruby
		elif pm_name == 'cargo':
			language=LanguageEnum.rust
		elif pm_name == 'packagist':
			language = LanguageEnum.php
		else:
			raise Exception(f'Package manager {pm_name} is not supported!')
	except Exception as e:
		msg_fail(str(e))
		return risks, report

	# analyze package composition
	try:
		num_files, lang_files, bin_files, num_funcs, total_loc = parse_package_composition(
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
		msg_ok(content)
		report['composition'] = {
			'num_files' : num_files,
			'num_funcs' : num_funcs,
			'num_bins'	: bin_files,
			f'{lang_file_ext}_files': lang_files,
			'Loc'		: total_loc,
		}
	except Exception as e:
		msg_fail(str(e))

	# check if this package contains executables or other binary blobs and alert the user
	try:
		msg_info('Checking for binaries (.exe/.so)...', end='', flush=True, indent=1)
		if bin_files:
			reason = f'found {bin_files} binaries'
			alert_type = 'contains executables or other binaries'
			risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
			msg_alert(reason)
		else:
			msg_ok('none found')
	except Exception as e:
		msg_fail(str(e))

	#
	# check if this package is a noisy package:
	# i.e., typo-guard, placeholder, dummy, empty, or troll package
	#
	try:
		msg_info('Checking if dummy/troll package...', end='', flush=True, indent=1)
		if num_funcs == 0 or (not report.get('permissions', None) and
				not report.get('dependencies', None) and
				num_funcs <= 5 and lang_files <= 1):
			reason = 'dummy/empty or troll package'
			alert_type = 'noisy package'
			risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
			msg_alert(reason)
		else:
			msg_ok(f'{num_funcs} funcs across {lang_files} {lang_file_ext} files ({total_loc} Loc)')
	except Exception as e:
		msg_fail(str(e))
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
		msg_info('Analyzing code...', end='', flush=True)
		cwd = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
		config_dir= os.path.join(cwd, 'config')
		if pm_name == 'pypi' or pm_name == 'local_python':
			language=LanguageEnum.python
			configpath = os.path.join(config_dir,'astgen_python_smt.config')
			system = 'python2'
		elif pm_name == 'npm' or pm_name == 'local_nodejs':
			language=LanguageEnum.javascript
			configpath = os.path.join(config_dir,'astgen_javascript_smt.config')
			system = 'python'
		elif pm_name == 'rubygems':
			language=LanguageEnum.ruby
			configpath = os.path.join(config_dir,'astgen_ruby_smt.config')
			system = 'ruby'
		elif pm_name == 'cargo':
			language=LanguageEnum.rust
			configpath = os.path.join(config_dir,'astgen_rust_smt.config')
			system = 'rust'
		elif pm_name == 'packagist':
			language = LanguageEnum.php
			configpath = os.path.join(config_dir, 'astgen_php_smt.config')
			system = 'php'
		else:
			raise Exception(f'Package manager {pm_name} is not supported!')
	except Exception as e:
		msg_fail(str(e))
		return risks, report

	# analyze code for APIs
	try:
		static = get_static_proxy_for_language(language=language)
		if pm_name =='packagist':
			perms = static.get_perms(inpath=filepath, outfile=filepath+'.out', root=None, configpath=configpath,
				pkg_name=pkg_name, pkg_version=ver_str, evaluate_smt=False)
		else:
			try:
				static.astgen(inpath=filepath, outfile=filepath+'.out', root=None, configpath=configpath,
					pkg_name=pkg_name, pkg_version=ver_str, evaluate_smt=False)
			except Exception as e:
				logging.debug('Failed to parse: %s', str(e))
				raise Exception('parse error: is %s installed?' % (system))

			assert os.path.exists(filepath+'.out'), 'parse error!'
			perms = parse_api_usage(pm_name, filepath+'.out')
		if not perms:
			msg_ok('no perms found')
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

		msg_alert(f'needs {len(perms_needed)} perm(s): {",".join(perms_needed)}')
		report['permissions'] = report_data
	except Exception as e:
		report['permissions'] = ' N/A'
		msg_fail(str(e))

	# Analyze risky API sequence (e.g., decode+exec)
	try:
		msg_info('Analyzing risky API sequence...', end='', flush=True, indent=1)
		# TODO
		msg_warn(' N/A','Coming soon!')
	except Exception as e:
		msg_fail(str(e))
	finally:
		return risks, report

def trace_installation(pm_enum, pkg_name, ver_str, report_dir, risks, report):
	try:
		msg_info('Installing package and tracing code...', end='', flush=True)

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
		msg_ok(f'found {out} syscalls')
	except Exception as e:
		msg_fail(str(e))
	finally:
		return risks, report

def analyze_manifest_confusion(pm_name, pm_proxy, pkg_name, ver_str, filepath, risks, report):
	try:
		msg_info('Checking for manifest confusion...', end='', flush=True)
		if pm_name == 'npm':
			mc_data, error = pm_proxy.npm_manifest_confusion(pkg_name, ver_str, filepath)
			report['manifest_confusion'] = mc_data
			if error:
				if error == 'KeyError':
					reason = 'No dependencies exists in package.json '
					alert_type = 'No dependencies'
				elif error == 'Confusion':
					reason = f'Manifest confusion deps:{mc_data}'
					alert_type = 'manifest confusion'
				risks = alert_user(alert_type, THREAT_MODEL, reason, risks)
				msg_alert(reason)
				return risks, report
			else:
				msg_ok('No manifest confusion')
		else:
			report['manifest_confusion'] = ' N/A'
			msg_warn(' N/A','Coming soon!')
	except Exception as e:
		print(str(e))
	finally:
		return risks, report

def audit(pm_args, pkg_name, ver_str, report_dir, extra_args, config):

	pm_enum, pm_name, pm_proxy = pm_args
	host_volume, container_mountpoint, install_trace = extra_args

	msg_info('===============================================')
	msg_info(f'Auditing {pm_name} package {pkg_name} (ver: {ver_str if ver_str else "latest"})')
	msg_info('===============================================')

	# get version metadata
	try:
		msg_info(f"Fetching '{pkg_name}' from {pm_name}...", end='', flush=True)
		pkg_name, pkg_info = pm_proxy.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
		assert pkg_info, 'package not found!'

		ver_info = pm_proxy.get_version(pkg_name, ver_str=ver_str, pkg_info=pkg_info)
		assert ver_info, 'No version info!'

		if not ver_str:
			ver_str = ver_info['tag']

		msg_ok(f'ver {ver_str}')
	except Exception as e:
		msg_fail(str(e))
		return None

	risks = {}
	report = {
		'pm_name' : pm_name,
		'pkg_name' : pkg_name,
		'pkg_ver' : ver_str,
	}

	# analyze metadata
	risks, report = analyze_pkg_descr(pm_proxy, pkg_name, ver_str, pkg_info, risks, report)
	risks, report, release_history = analyze_release_history(pm_proxy, pkg_name, pkg_info, risks, report)
	risks, report = analyze_yanked_releases(pm_proxy, pkg_name, pkg_info, risks, report, release_history)
	risks, report = analyze_version(pm_proxy, pkg_name, ver_info, risks, report)
	risks, report = analyze_release_time(pm_proxy, pkg_name, ver_str, pkg_info, risks, report, release_history)
	risks, report = analyze_author(pm_proxy, pkg_name, ver_str, pkg_info, ver_info, risks, report)
	risks, report = analyze_readme(pm_proxy, pkg_name, ver_str, pkg_info, risks, report)
	risks, report = analyze_homepage(pm_proxy, pkg_name, ver_str, pkg_info, risks, report)
	risks, report = analyze_downloads(pm_proxy, pkg_name, pkg_info, risks, report)
	risks, report = analyze_zero_width_unicode(pm_proxy, pkg_name, pkg_info, risks, report)
	risks, report = analyze_install_hooks(pm_proxy, pkg_name, pkg_info, risks, report)
	risks, report = analyze_typosquatting(pm_proxy, pkg_name, pkg_info, risks, report)
	risks, report = analyze_dep_confusion(pm_proxy, pkg_name, pkg_info, risks, report)
	risks, report = analyze_repo_url(pm_proxy, pkg_name, ver_str, pkg_info, ver_info, risks, report)
	if 'repo' in report and 'url' in report['repo'] and report['repo']['url']:
		risks, report = analyze_repo_data(config, risks, report)
		if 'description' in report['repo']:
			risks, report = analyze_repo_descr(risks, report)
		risks, report = analyze_repo_code(risks, report)
		risks, report = analyze_repo_activity(risks, report)
	risks, report = analyze_cves(pm_name, pkg_name, ver_str, risks, report)
	risks, report = analyze_deps(pm_proxy, pkg_name, ver_str, pkg_info, ver_info, risks, report)

	# download package
	filepath = None
	if not os.path.isdir(pkg_name):
		try:
			msg_info(
				f"Downloading package from {pm_name}...",
				end='',
				flush=True
			)
			filepath, size = download_file(ver_info['url'])
			msg_ok(f'{float(size)/1024:.2f} KB')
		except KeyError:
			msg_fail('URL missing')
		except Exception as e:
			msg_fail(str(e))
	else:
		filepath = pkg_name
	
	# performs manifest confusion
	if filepath:
		risks, report = analyze_manifest_confusion(pm_name, pm_proxy, pkg_name, ver_str, filepath, risks, report)

	# perform static analysis
	if filepath:
		risks, report = analyze_apis(pm_name, pkg_name, ver_str, filepath, risks, report)
		risks, report = analyze_composition(pm_name, pkg_name, ver_str, filepath, risks, report)

	# perform dynamic analysis if requested
	if install_trace:
		risks, report = trace_installation(pm_enum, pkg_name, ver_str, report_dir, risks, report)

	# aggregate risks
	if not risks:
		msg_info('No risks found!')
		report['risks'] = None
	else:
		msg_info(
			f'{sum(len(v) for v in risks.values())} risk(s) apply to you, '
			f'package is {", ".join(risks.keys())}!'
		)
		report['risks'] = risks

	# generate final report
	args = (container_mountpoint, report_dir, host_volume)
	generate_package_report(report, args)

	# report link
	if pm_enum == PackageManagerEnum.pypi:
		msg_info(f'=> View pre-vetted package report at https://packj.dev/package/PyPi/{pkg_name}/{ver_str}')
	return report

def __get_pm_args(pm_name):
	pm_name = pm_name.lower()
	pm_enum = get_pm_enum(pm_name)
	pm_proxy = get_pm_proxy(pm_enum, cache_dir=None, isolate_pkg_info=False)
	return pm_enum, pm_name, pm_proxy

def parse_request_args(args):
	install_trace = False
	host_volume = None
	container_mountpoint = None

	# XXX expects host volume to be mounted inside container
	if in_docker() or in_podman():
		container_mountpoint = '/tmp/packj'
		host_volume = is_mounted(container_mountpoint)
		if not host_volume or not os.path.exists(container_mountpoint):
			msg_info(f'Missing host volume at {container_mountpoint}. Run Docker/Podman with "-v /tmp:{container_mountpoint}" argument.')
			exit(1)

	# build list of packages to audit
	audit_pkg_list = []
	for item in args.depfiles:
		try:
			assert ':' in item, f'invalid dep file: {item}. Expected <pm>:<file> (e.g., npm:package.json)'

			pm_name, deps_filepath = item.split(':')
			assert os.path.exists(deps_filepath), f'file does not exist'

			pm_enum, pm_name, pm_proxy = __get_pm_args(pm_name)

			dep_list = pm_proxy.parse_deps_file(deps_filepath)
			assert dep_list, "parse error"

			# iterate and build list of packages
			for pkg_name, ver_str in dep_list:
				audit_pkg_list.append(((pm_enum, pm_name, pm_proxy), pkg_name, ver_str))
		except Exception as e:
			msg_info(f'Failed to parse file "{item}" for dependencies: {str(e)}. Ignoring')

	for item in args.packages:
		try:
			components = item.split(':')
			assert len(components) >= 2 and len(components) <= 3, f'Invalid request: {item}. Expected <pm>:<pkg>[:<ver>] (e.g., npm:react)'

			if len(components) == 2: item += ':'
			pm_name, pkg_name, ver_str = item.split(':')
			pm_enum, pm_name, pm_proxy = __get_pm_args(pm_name)

			audit_pkg_list.append(((pm_enum, pm_name, pm_proxy), pkg_name, ver_str))
		except Exception as e:
			msg_info(f'Failed to parse input "{item}" {str(e)}. Ignoring')

	# create a temp dir to host debug logs, trace logs, and final report
	try:
		report_dir = tempfile.mkdtemp(prefix=f'packj_audit_', dir=container_mountpoint)
		os.chmod(report_dir, 0o755)
	except Exception as e:
		msg_info(f'Failed to create temp dir: {str(e)}!')
		exit(1)

	# enable debugging if requested
	if args.debug:
		try:
			_, filename = tempfile.mkstemp(prefix='debug_', dir=report_dir, suffix='.log')
			print(f'\n*** NOTE: Running in debug mode (log: {filename}) ***\n')
			logging.basicConfig(filename=filename, datefmt='%H:%M:%S', level=logging.DEBUG,
								format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s')
		except Exception as e:
			msg_info(f'Failed to create debug log: {str(e)}. Using stdout.')
			logging.getLogger().setLevel(logging.DEBUG)
	else:
		logging.getLogger().setLevel(logging.ERROR)

	# check if installation trace has been requested
	if args.trace:
		if not (in_docker() or in_podman()):
			print(f'*** You\'ve requested package installation trace *** We recommend running in Docker/Podman. Continue (N/y): ', end='')
			stop = input()
			if stop != 'y':
				exit(0)
		install_trace = True

	return audit_pkg_list, report_dir, (host_volume, container_mountpoint, install_trace)

def main(args, config_file):

	# get user threat model
	config = build_threat_model(config_file)

	# parse input
	audit_pkg_list, report_dir, cmd_args = parse_request_args(args)

	# audit each package
	reports = []
	for pkg_info in audit_pkg_list:
		report = audit(*pkg_info, report_dir, cmd_args, config)
		if report:
			reports.append(report)

	# generate summarized report
	msg_info('=============================================')
	generate_summary(reports, report_dir, cmd_args)
 