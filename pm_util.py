from util.enum_util import PackageManagerEnum, LanguageEnum

def get_pm_install_cmd(pm_enum, pkg_name, ver_str):
	if pm_enum == PackageManagerEnum.pypi:
		base_cmd = f'pip3 install --quiet --no-warn-script-location --disable-pip-version-check '
		ver_cmd = f'=={ver_str}'
	elif pm_enum == PackageManagerEnum.npmjs:
		base_cmd = f'npm install --silent --no-progress --no-update-notifier '
		ver_cmd = f'@{ver_str}'
	elif pm_enum == PackageManagerEnum.rubygems:
		base_cmd = f'gem install --user --silent '
		ver_cmd = f' -v {ver_str}'
	else:
		raise Exception(f'Package manager {pm_enum} is not supported')

	cmd = base_cmd + f'{pkg_name}'
	if ver_str:
		cmd += ver_cmd
	return cmd

def get_pm_enum(pm_name):
	if pm_name == 'pypi':
		return PackageManagerEnum.pypi
	elif pm_name == 'npm':
		return PackageManagerEnum.npmjs
	elif pm_name == 'rubygems':
		return PackageManagerEnum.rubygems
	else:
		raise Exception(f'Package manager {pm_name} is not supported')

def get_pm_proxy_for_language(language, registry=None, cache_dir=None, isolate_pkg_info=False):
	from util.enum_util import LanguageEnum
	if language == LanguageEnum.python:
		from pm_proxy.pypi import PypiProxy
		return PypiProxy(registry=registry, cache_dir=cache_dir, isolate_pkg_info=isolate_pkg_info)
	elif language == LanguageEnum.javascript:
		from pm_proxy.npmjs import NpmjsProxy
		return NpmjsProxy(registry=registry, cache_dir=cache_dir, isolate_pkg_info=isolate_pkg_info)
	elif language == LanguageEnum.ruby:
		from pm_proxy.rubygems import RubygemsProxy
		return RubygemsProxy(registry=registry, cache_dir=cache_dir, isolate_pkg_info=isolate_pkg_info)
	else:
		raise Exception("PM proxy not available for language: %s" % language)

def get_pm_proxy(pm, registry=None, cache_dir=None, isolate_pkg_info=False):
	from util.enum_util import PackageManagerEnum
	if pm == PackageManagerEnum.pypi:
		from pm_proxy.pypi import PypiProxy
		return PypiProxy(registry=registry, cache_dir=cache_dir, isolate_pkg_info=isolate_pkg_info)
	elif pm == PackageManagerEnum.npmjs:
		from pm_proxy.npmjs import NpmjsProxy
		return NpmjsProxy(registry=registry, cache_dir=cache_dir, isolate_pkg_info=isolate_pkg_info)
	elif pm == PackageManagerEnum.rubygems:
		from pm_proxy.rubygems import RubygemsProxy
		return RubygemsProxy(registry=registry, cache_dir=cache_dir, isolate_pkg_info=isolate_pkg_info)
	else:
		raise Exception("PM proxy not available for package manager: %s" % pm)

