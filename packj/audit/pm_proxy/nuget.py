import logging
import requests
import dateutil.parser
from os.path import join, exists

from packj.audit.pm_proxy.pm_base import PackageManagerProxy


class NugetProxy(PackageManagerProxy):
    # Understanding NuGet v3 feeds
    # https://emgarten.com/posts/understanding-nuget-v3-feeds
    def __init__(self, registry=None, cache_dir=None, isolate_pkg_info=False):
        super(NugetProxy, self).__init__()
        self.registry = registry
        self.cache_dir = cache_dir
        self.isolate_pkg_info = isolate_pkg_info
        self.metadata_format = 'json'
        self.dep_format = 'json'
        self.name = 'nuget'

    def get_metadata(self, pkg_name, pkg_version=None):
        # fetch metadata from json api
        pkg_name = pkg_name.lower()
        metadata_url = f'https://api.nuget.org/v3/registration5-semver1/{pkg_name}/index.json'
        try:
            resp = requests.request('GET', metadata_url)
            resp.raise_for_status()
            pkg_info = resp.json()
            if pkg_info:
                try:
                    pkg_name = pkg_info['items'][0]['items'][0]['catalogEntry']['id']
                except KeyError:
                    pass
        except Exception as e:
            print(str(e))
            logging.debug("Fail in get_metadata for pkg %s, ignoring!\n%s",pkg_name,str(e))
            pkg_info=None
        finally:
            return pkg_name, pkg_info

    def get_version(self, pkg_name, pkg_info=None, ver_str=None):
        if not pkg_info:
            _, pkg_info = self.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
        assert pkg_info and 'items' in pkg_info, "Failed to fetch metadata!"

        if not ver_str:
            vers_info = pkg_info['items'][0]['items'][-1]
            ver_str = vers_info['catalogEntry']['version']

        for ver_data in pkg_info['items'][0]['items']:
            if ver_data['catalogEntry']['version'] == ver_str:
                tag = ver_str
                url = ver_data['packageContent']
                uploaded = ver_data['commitTimeStamp']
                return {'tag':tag, 'url':url, 'uploaded':uploaded}
        return None

    def get_download_url(self, pkg_name, ver_str=None, pkg_info=None):
        try:
            if not pkg_info:
                _, pkg_info = self.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
            assert pkg_info and 'package' in pkg_info, "Failed to fetch metadata!"

            info = self.get_version(pkg_name=pkg_name, pkg_info=pkg_info)
            if info:
                return info['url']

            raise Exception('No download info found!')
        except Exception as e:
            logging.warning(str(e))
            return None

    def get_downloads(self, pkg_name, pkg_info=None):
        # No downloads mentioned in the API
        pass

    def get_description(self, pkg_name, ver_str=None, pkg_info=None):
        try:
            if not pkg_info:
                _, pkg_info = self.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
            assert pkg_info and 'items' in pkg_info, "Failed to fetch metadata!"

            if not ver_str:
                vers_info = pkg_info['items'][0]['items'][-1]
                ver_str = vers_info['catalogEntry']['version']

            for ver_data in pkg_info['items'][0]['items']:
                if ver_data['catalogEntry']['version'] == ver_str:
                    description = ver_data['catalogEntry']['description']

            if description and len(description):
                return description


            raise Exception(' No description found in metadata!')
        except Exception as e:
            logging.warning(str(e))
            return None

    def get_repo(self, pkg_name, ver_str=None, pkg_info=None, ver_info=None):
        try:
            if not pkg_info:
                _, pkg_info = self.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
            assert pkg_info and 'items' in pkg_info, "Failed to fetch metadata!"

            if not ver_str:
                vers_info = pkg_info['items'][0]['items'][-1]
                ver_str = vers_info['catalogEntry']['version']

            for ver_data in pkg_info['items'][0]['items']:
                if ver_data['catalogEntry']['version'] == ver_str:
                    repo = ver_data['catalogEntry']['projectUrl']

            if repo:
                return repo
            raise Exception('No repository found in metadata!')
        except Exception as e:
            logging.warning(str(e))
            return None

    def get_author(self, pkg_name, ver_str=None, pkg_info=None, ver_info=None):
        try:
            if not pkg_info:
                _, pkg_info = self.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
            assert pkg_info and 'items' in pkg_info, "Failed to fetch metadata!"

            if not ver_str:
                vers_info = pkg_info['items'][0]['items'][-1]
                ver_str = vers_info['catalogEntry']['version']

            for ver_data in pkg_info['items'][0]['items']:
                if ver_data['catalogEntry']['version'] == ver_str:
                    author = ver_data['catalogEntry']['authors']

            if author:
                return author
            raise Exception('No repository found in metadata!')
        except Exception as e:
            logging.warning(str(e))
            return None

    def get_homepage(self, pkg_name, ver_str=None, pkg_info=None):
        # No downloads mentioned in the API
        pass

    def get_readme(self, pkg_name, ver_str=None, pkg_info=None):
        try:
            if not pkg_info:
                _, pkg_info = self.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
            assert pkg_info and 'items' in pkg_info, "Failed to fetch metadata!"

            if not ver_str:
                vers_info = pkg_info['items'][0]['items'][-1]
                ver_str = vers_info['catalogEntry']['version']

            for ver_data in pkg_info['items'][0]['items']:
                if ver_data['catalogEntry']['version'] == ver_str:
                    readME = ver_data['catalogEntry']['readmeUrl']
            if readME:
                return readME
            raise Exception('No repository found in metadata!')
        except Exception as e:
            logging.warning(str(e))
            return None

    def get_dependencies(self, pkg_name, ver_str=None, pkg_info=None, ver_info=None):
        try:
            if not pkg_info:
                _, pkg_info = self.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
            assert pkg_info and 'items' in pkg_info, "Failed to fetch metadata!"

            if not ver_str:
                vers_info = pkg_info['items'][0]['items'][-1]
                ver_str = vers_info['catalogEntry']['version']

            for ver_data in pkg_info['items'][0]['items']:
                if ver_data['catalogEntry']['version'] == ver_str:
                    depGroup = ver_data['catalogEntry']['dependencyGroups']

            dep_list = []
            for eachDG in depGroup:
                if 'PackageDependencyGroup' == eachDG['@type']:
                    for deps in eachDG['dependencies']:
                        if deps['@type'] == 'PackageDependency':
                            dep_list.append(deps['id'])
            if dep_list:
                return dep_list
            raise Exception('No dependencies found in metadata!')
        except Exception as e:
            logging.warning(str(e))
            return None


    def get_release_history(self, pkg_name, pkg_info=None, max_nums=-1):
        from packj.util.dates import datetime_delta, datetime_to_date_str

        if not pkg_info:
            _, pkg_info = self.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
        assert pkg_info and 'items' in pkg_info, "Failed to fetch metadata!"

        vers_info = pkg_info['items'][0]['items']
        vers_info = vers_info[::-1]

        history = {}
        last_date = None
        for ver_data in vers_info:
            try:
                date = dateutil.parser.parse(ver_data['commitTimeStamp'])
            except:
                date = None
            days = None
            if date or last_date:
                try:
                    days = datetime_delta(date, date2=last_date, days=True)
                except:
                    pass
            last_date = date

            history[ver_data['catalogEntry']['version']] = {
                'release_date':datetime_to_date_str(date),
                'days_since_last_release': days,
                'yanked': False,
            }
        return history

    def get_maintainers(self, pkg_name:str, ver_str:str=None, pkg_info:dict=None, ver_info:dict=None):
        pass