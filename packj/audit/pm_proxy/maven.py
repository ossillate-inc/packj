import os
import json
import requests
import logging
from os.path import join, exists, basename, expanduser
from xml.etree.ElementTree import fromstring, tostring

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

    def _get_versions_info(self, pkg_name):
        gid, aid = pkg_name.split('/')
        try:
            # Maven URL for package information
            # https://repo1.maven.org/maven2/com/google/protobuf/protobuf-java/maven-metadata.xml
            versions_url = "https://repo1.maven.org/maven2/%s/%s/maven-metadata.xml" % (gid.replace('.', '/'), aid)
            versions_content = requests.request('GET', versions_url)
            # Parsing pom files
            # https://stackoverflow.com/questions/16802732/reading-maven-pom-xml-in-python
            return fromstring(versions_content.text)
        except:
            logging.error("fail to get latest version for pkg %s!", pkg_name)
            return None

    def _get_latest_version(self, pkg_name):
        versions_info = self._get_versions_info(pkg_name=pkg_name)
        if versions_info:
            return versions_info.find('./versioning/latest').text
        else:
            return None
    
    def _get_sanitized_version(self, pkg_name, pkg_version):
        if pkg_version is None:
            return self._get_latest_version(pkg_name=pkg_name)
        else:
            return pkg_version

    def get_metadata(self, pkg_name, pkg_version=None):
        # load cached metadata information
        pkg_info_dir = self.get_pkg_info_dir(pkg_name=pkg_name)
        if pkg_info_dir is not None:
            metadata_fname = self.get_metadata_fname(pkg_name=pkg_name, pkg_version=pkg_version, fmt= self.metadata_format)
            metadata_file = join(pkg_info_dir, metadata_fname)
            if exists(metadata_file):
                logging.warning("get_metadata: using cached metadata_file %s!", metadata_file)
                if self.metadata_format == 'pom':
                    return fromstring(open(metadata_file, 'r').read())
                else:
                    logging.error("get_metadata: output format %s is not supported!", self.metadata_format)
                    return None
        # Maven metadata is loaded in two steps
        # First load names and versions. Then load the latest/specific version
        try:
            # Maven URL for specific version
            # e.g, https://repo1.maven.org/maven2/com/google/protobuf/protobuf-java/3.6.1/protobuf-java-3.6.1.pom
            metadata_url = "https://repo1.maven.org/maven2/%s" % self._get_pkg_path(
                pkg_name=pkg_name, pkg_version=self._get_sanitized_version(pkg_name=pkg_name, pkg_version=pkg_version),
                suffix="pom")
            metadata_content = requests.request('GET', metadata_url)
            pkg_info = fromstring(metadata_content.text)
        except Exception as e:
            logging.error("fail in get_metadata for pkg %s: %s, ignoring!", pkg_name, str(e))
            return None
        if pkg_info_dir is not None:
            if not exists(pkg_info_dir):
                os.makedirs(pkg_info_dir)
            metadata_fname = self.get_metadata_fname(pkg_name=pkg_name, pkg_version=pkg_version,
                                                     fmt=self.metadata_format)
            metadata_file = join(pkg_info_dir, metadata_fname)
            if self.metadata_format == 'pom':
                open(metadata_file, 'w').write(metadata_content.text)
            else:
                logging.error("get_metadata: output format %s is not supported!", self.metadata_format)
        return pkg_info