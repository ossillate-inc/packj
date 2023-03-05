from packj.util.enum_util import PackageManagerEnum, LanguageEnum

def get_pm_install_cmd(pm_enum, pkg_name, ver_str, quiet=True):
	if pm_enum == PackageManagerEnum.pypi:
		base_cmd = 'pip3 install '
		quiet_args = '--quiet --no-warn-script-location --disable-pip-version-check '
		ver_cmd = f'=={ver_str}'
	elif pm_enum == PackageManagerEnum.npmjs:
		base_cmd = f'npm install'
		quiet_args = ' --silent --no-progress --no-update-notifier '
		ver_cmd = f'@{ver_str}'
	elif pm_enum == PackageManagerEnum.rubygems:
		base_cmd = 'gem install --user'
		quiet_args = ' --silent '
		ver_cmd = f' -v {ver_str}'
	else:
		raise Exception(f'Package manager {pm_enum} is not supported')

	cmd = base_cmd
	if quiet:
		cmd += quiet_args
	cmd += f'{pkg_name}'
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
	elif pm_name == 'local_node':
		return PackageManagerEnum.local_node
	else:
		raise Exception(f'Package manager {pm_name} is not supported')

def get_pm_proxy_for_language(language, registry=None, cache_dir=None, isolate_pkg_info=False):
	from packj.util.enum_util import LanguageEnum
	if language == LanguageEnum.python:
		from packj.audit.pm_proxy.pypi import PypiProxy
		return PypiProxy(registry=registry, cache_dir=cache_dir, isolate_pkg_info=isolate_pkg_info)
	elif language == LanguageEnum.javascript:
		from packj.audit.pm_proxy.npmjs import NpmjsProxy
		return NpmjsProxy(registry=registry, cache_dir=cache_dir, isolate_pkg_info=isolate_pkg_info)
	elif language == LanguageEnum.ruby:
		from packj.audit.pm_proxy.rubygems import RubygemsProxy
		return RubygemsProxy(registry=registry, cache_dir=cache_dir, isolate_pkg_info=isolate_pkg_info)
	else:
		raise Exception("PM proxy not available for language: %s" % language)

def get_pm_proxy(pm, registry=None, cache_dir=None, isolate_pkg_info=False):
	from packj.util.enum_util import PackageManagerEnum
	if pm == PackageManagerEnum.pypi:
		from packj.audit.pm_proxy.pypi import PypiProxy
		return PypiProxy(registry=registry, cache_dir=cache_dir, isolate_pkg_info=isolate_pkg_info)
	elif pm == PackageManagerEnum.npmjs:
		from packj.audit.pm_proxy.npmjs import NpmjsProxy
		return NpmjsProxy(registry=registry, cache_dir=cache_dir, isolate_pkg_info=isolate_pkg_info)
	elif pm == PackageManagerEnum.rubygems:
		from packj.audit.pm_proxy.rubygems import RubygemsProxy
		return RubygemsProxy(registry=registry, cache_dir=cache_dir, isolate_pkg_info=isolate_pkg_info)
	elif pm == PackageManagerEnum.local_node:
		from packj.audit.pm_proxy.local_node import LocalNodeProxy
		return LocalNodeProxy(cache_dir=cache_dir, isolate_pkg_info=isolate_pkg_info)
	else:
		raise Exception("PM proxy not available for package manager: %s" % pm)
