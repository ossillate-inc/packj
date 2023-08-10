import os
import json
import logging
import requests
import dateutil.parser
from os.path import join, exists

from util.job_util import exec_command
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

    def _get_pkg_name(self, pkg_name, pkg_version=None, suffix='nupkg'):
        if pkg_version is None:
            return '%s.latest.%s' % (pkg_name, suffix)
        else:
            return '%s.%s.%s' % (pkg_name, pkg_version, suffix)

    def get_metadata(self, pkg_name, pkg_version=None):
        # load cached metadata information
        pkg_info_dir = self.get_pkg_info_dir(pkg_name=pkg_name)
        if pkg_info_dir is not None:
            metadata_fname = self.get_metadata_fname(pkg_name=pkg_name, pkg_version=pkg_version,
                                                     fmt=self.metadata_format)
            metadata_file = join(pkg_info_dir, metadata_fname)
            if exists(metadata_file):
                logging.warning("get_metadata: using cached metadata_file %s!", metadata_file)
                if self.metadata_format == 'json':
                    try:
                        return json.load(open(metadata_file, 'r'))
                    except:
                        logging.debug("fail to load metadata_file: %s, regenerating!", metadata_file)
                else:
                    logging.error("get_metadata: output format %s is not supported!", self.metadata_format)
                    return None
        # fetch metadata from json api
        if pkg_version:
            metadata_url = "https://api.nuget.org/v3/registration1/%s/%s.json" % (pkg_name.lower(), pkg_version.lower())
        else:
            metadata_url = "https://api.nuget.org/v3/registration1/%s/index.json" % pkg_name.lower()
        try:
            metadata_content = requests.request('GET', metadata_url)
            pkg_info = json.loads(metadata_content.text)
        except:
            logging.error("fail in get_metadata for pkg %s, ignoring!", pkg_name)
            return None
        # optionally cache metadata
        if pkg_info_dir is not None:
            if not exists(pkg_info_dir):
                os.makedirs(pkg_info_dir)
            metadata_fname = self.get_metadata_fname(pkg_name=pkg_name, pkg_version=pkg_version,
                                                     fmt=self.metadata_format)
            metadata_file = join(pkg_info_dir, metadata_fname)
            if self.metadata_format == 'json':
                json.dump(pkg_info, open(metadata_file, 'w'), indent=2)
            else:
                logging.error("get_metadata: output format %s is not supported!", self.metadata_format)
        return pkg_info

    def get_versions(self, pkg_name, max_num=15, min_gap_days=30, with_time=False):
        pkg_info = self.get_metadata(pkg_name=pkg_name)
        if pkg_info is None or 'items' not in pkg_info:
            return []
        # published, version
        version_date = []
        for versions_info in pkg_info['items']:
            for item_info in versions_info['items']:
                version_date.append((item_info['version'], dateutil.parser.parse(item_info['published'])))
        return self.filter_versions(version_date=version_date, max_num=max_num, min_gap_days=min_gap_days,
                                    with_time=with_time)

    def get_author(self, pkg_name):
        pkg_info = self.get_metadata(pkg_name=pkg_name)
        if pkg_info is None or 'items' not in pkg_info:
            return {}
        authors = set()
        for versions_info in pkg_info['items']:
            if 'items' not in versions_info:
                continue
            authors.update([item_info['authors'] for item_info in versions_info['items']])
        return {'authors': list(authors)}
