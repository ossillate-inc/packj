def get_pm_proxy_for_language(language, registry=None, cache_dir=None, isolate_pkg_info=False):
	from util.enum_util import LanguageEnum
	if language == LanguageEnum.python:
		from pm_proxy.pypi import PypiProxy
		return PypiProxy(registry=registry, cache_dir=cache_dir, isolate_pkg_info=isolate_pkg_info)
	elif language == LanguageEnum.javascript:
		from pm_proxy.npmjs import NpmjsProxy
		return NpmjsProxy(registry=registry, cache_dir=cache_dir, isolate_pkg_info=isolate_pkg_info)
	else:
		raise Exception("Proxy not available for language: %s" % language)

def get_pm_proxy(pm, registry=None, cache_dir=None, isolate_pkg_info=False):
	from util.enum_util import PackageManagerEnum
	if pm == PackageManagerEnum.pypi:
		from pm_proxy.pypi import PypiProxy
		return PypiProxy(registry=registry, cache_dir=cache_dir, isolate_pkg_info=isolate_pkg_info)
	elif pm == PackageManagerEnum.npmjs:
		from pm_proxy.npmjs import NpmjsProxy
		return NpmjsProxy(registry=registry, cache_dir=cache_dir, isolate_pkg_info=isolate_pkg_info)
	else:
		raise Exception("Proxy not available for package manager: %s" % pm)

