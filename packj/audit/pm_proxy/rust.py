import requests
import logging

from packj.audit.pm_proxy.pm_base import PackageManagerProxy
class RustProxy(PackageManagerProxy):
    def __init__(self, registry=None, cache_dir=None, isolate_pkg_info=False):
        super(RustProxy, self).__init__()
        self.registry = registry
        self.cache_dir = cache_dir
        self.isolate_pkg_info = isolate_pkg_info
        self.metadata_format = 'json'
        self.dep_format = 'json'
        self.name = "cargo"
    def get_metadata(self, pkg_name, pkg_version=None):
        # Rust's Package managers --> crates.io
        # json api for package(with all versions details): https://crates.io/api/v1/crates/<package_name>
        # json api for a particular version: https://crates.io/api/v1/crates/<package_name>/<version>
        # fetch metadata from json api
        if pkg_version:
            metadata_url = f'https://crates.io/api/v1/crates/{pkg_name}/{pkg_version}'
        else:
            metadata_url = f'https://crates.io/api/v1/crates/{pkg_name}'
        try:
            resp = requests.request('GET',metadata_url)
            resp.raise_for_status()
            pkg_info = resp.json()
            if pkg_info and pkg_version:
                try:
                    pkg_name=pkg_info['version']['crate']
                except KeyError:
                    pass
            elif pkg_info:
                try:
                    pkg_name=pkg_info['versions'][0]['crate']
                except KeyError:
                    pass
        except Exception as e:
            logging.debug("Fail in get_metadata for pkg %s, ignoring!\n%s",pkg_name,str(e))
            pkg_info=None
        finally:
            return pkg_name, pkg_info
    def get_version(self, pkg_name, pkg_info=None, ver_str=None):
        if not pkg_info:
            _, pkg_info = self.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
        assert pkg_info and 'crate' in pkg_info, "Failed to fetch metedata!"
        if not ver_str:
            ver_str = pkg_info['crate']['newest_version']
        if 'versions' in pkg_info:
            for vers in pkg_info['versions']:
                return {'tag':ver_str, 'url':vers['dl_path'], 'uploaded':vers['created_at']}
        elif 'version' in pkg_info:
            return {'tag':ver_str, 'url':vers['dl_path'], 'uploaded':vers['created_at']}
        return None
    def get_download_url(self, pkg_name, ver_str=None, pkg_info=None):
        try:
            if not pkg_info:
                _, pkg_info = self.get_metadata(pkg_name=pkg_name,pkg_version=ver_str)
            assert pkg_info, "Failed to fetch metadata!"
            if 'versions' in pkg_info:
                return pkg_info['versions'][0]['dl_path']
            if 'version' in pkg_info:
                return pkg_info['version']['dl_path']
            raise Exception('No download info found in metadata')
        except Exception as e:
            logging.warning(str(e))
            return None
    def get_downloads(self, pkg_name, pkg_info=None):
        try:
            if not pkg_info:
                pkg_info = self.get_metadata(pkg_name=pkg_name)
            assert pkg_info, "Failed to fetch metadata!"
            return int(pkg_info['crate']['downloads'])
        except Exception as e:
            logging.warning("Error fetching downloads: %s"%str(e))
            return None
        
        