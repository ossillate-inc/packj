import shutil
import tempfile
import logging

from os.path import abspath

from util.enum_util import LanguageEnum
from util.enum_util import PackageManagerEnum
from pm_proxy.pypi import PypiProxy

def get_pm_proxy_for_language(language, registry=None, cache_dir=None, isolate_pkg_info=False):
    if language == LanguageEnum.python:
        return PypiProxy(registry=registry, cache_dir=cache_dir, isolate_pkg_info=isolate_pkg_info)
    else:
        raise Exception("Proxy not available for language: %s" % language)

def get_pm_proxy(pm, registry=None, cache_dir=None, isolate_pkg_info=False):
    if pm == PackageManagerEnum.pypi:
        return PypiProxy(registry=registry, cache_dir=cache_dir, isolate_pkg_info=isolate_pkg_info)
    else:
        raise Exception("Proxy not available for package manager: %s" % pm)

def get_metadata(pkg_name, language, cache_dir=None, pkg_version=None, isolate_pkg_info=False):
    if cache_dir:
        cache_dir = abspath(cache_dir)
    # Get metadata and versions
    pm_proxy = get_pm_proxy_for_language(language=language, cache_dir=cache_dir, isolate_pkg_info=isolate_pkg_info)
    pkg_info = pm_proxy.get_metadata(pkg_name=pkg_name, pkg_version=pkg_version)
    pkg_versions = pm_proxy.get_versions(pkg_name=pkg_name, max_num=-1)
    #logging.warning("pkg %s has %d versions", pkg_name, len(pkg_versions))
    #logging.info("pkg %s has info %s and versions %s", pkg_name, pkg_info, pkg_versions)
