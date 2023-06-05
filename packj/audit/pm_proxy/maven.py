import os
import json

from packj.util.job_util import exec_command
from packj.audit.pm_proxy.pm_base import PackageManagerProxy

class MavenProxy(PackageManagerProxy):
    def __init__(self, registry=None, cache_dir=None, isolated_pkg_info=False):
        super(MavenProxy, self).__init__()
        self.registry = registry
        self.cache_dir = cache_dir
        self.isolate_pkg_info = isolated_pkg_info
        self.metadata_format = 'pom'
        self.dep_format = 'json'
        
    def get_metadata(self, pkg_name, pkg_version=None):
        pass