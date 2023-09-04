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
        
    def get_metadata(self, pkg_name, pkg_version=None):
        if not pkg_version:
            pkg_version = self._get_versions_info(pkg_name=pkg_name)
        actual_pkg_name = pkg_name.split('.')[-1]
        url_pass = pkg_name.replace('.', '/') +'/'+pkg_version+'/'+actual_pkg_name+'-'+pkg_version+'.pom'
        metadata_url = f'https://repo1.maven.org/maven2/{url_pass}'
        
        try:
            resp = requests.request('GET', metadata_url)
            resp.raise_for_status()
            pkg_info = fromstring(resp.text)
        except Exception as e:
            logging.debug("Fail in get_metadata for pkg %s, ignoring!\n%s",pkg_name,str(e))
            pkg_info=None
        finally:
            return pkg_name, pkg_info

    def _get_versions_info(self, pkg_name):
        try:
            # Maven URL for package information
            # https://repo1.maven.org/maven2/com/google/protobuf/protobuf-java/maven-metadata.xml
            versions_url = "https://repo1.maven.org/maven2/%s/maven-metadata.xml" % (pkg_name.replace('.', '/'))
            versions_content = requests.request('GET', versions_url)
            # Parsing pom files
            # https://stackoverflow.com/questions/16802732/reading-maven-pom-xml-in-python
            versions_info = fromstring(versions_content.text)
            if versions_info:
                    return versions_info.find('./versioning/latest').text
            else:
                return None
        except:
            logging.error("fail to get latest version for pkg %s!", pkg_name)
            return None

    def get_version(self, pkg_name, ver_str=None, pkg_info=None):
        ver_str = self._get_versions_info(pkg_name=pkg_name)
        actual_pkg_name = pkg_name.split('.')[-1]
        url_pass = pkg_name.replace('.', '/') +'/'+ver_str+'/'+actual_pkg_name+'-'+ver_str+'.jar'
        dwn_url = f'https://repo1.maven.org/maven2/{url_pass}'
        return {'tag':ver_str, 'url':dwn_url, 'uploaded':None}
        
    def get_download_url(self, pkg_name, ver_str=None, pkg_info=None):
        try:
            if not ver_str:
                ver_str = self._get_versions_info(pkg_name=pkg_name)
            actual_pkg_name = pkg_name.split('.')[-1]
            url_pass = pkg_name.replace('.', '/') +'/'+ver_str+'/'+actual_pkg_name+'-'+ver_str+'.jar'
            dwn_url = f'https://repo1.maven.org/maven2/{url_pass}'
            
            return dwn_url
        except Exception as e:
            logging.warning(str(e))
            return None
    
    def get_description(self, pkg_name, ver_str=None, pkg_info=None):
        try:
            if not pkg_info:
                _, pkg_info = self.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
            assert pkg_info and 'package' in pkg_info, "Failed to fetch metadata!"
            
            namespace = {'ns': 'http://maven.apache.org/POM/4.0.0'}
            
            description = pkg_info.find('ns:description', namespace).text
            if description and len(description):
                return description.strip()
            
            raise Exception(' No description found in metadata!')
        except Exception as e:
            logging.warning(str(e))
            return None
    
    def get_repo(self, pkg_name, ver_str=None, pkg_info=None, ver_info=None):
        try:
            if not pkg_info:
                _, pkg_info = self.get_metadata(pkg_name=pkg_name)
            assert pkg_info and 'package' in pkg_info, "Failed to fetch metadata!"
            
            namespace = {'ns': 'http://maven.apache.org/POM/4.0.0'}
            
            repo_url = pkg_info.find('ns:url', namespace).text
            if repo_url:
                return repo_url
            
            raise Exception('No repository found in metadata!')
        except Exception as e:
            logging.warning(str(e))
            return None
    
    def get_author(self, pkg_name, ver_str=None, pkg_info=None, ver_info=None):
        try:
            if not pkg_info:
                _, pkg_info = self.get_metadata(pkg_name=pkg_name)
            assert pkg_info and 'package' in pkg_info, "Failed to fetch metadata!"
            
            nsmap = {'m': 'http://maven.apache.org/POM/4.0.0'}

            devs = pkg_info.findall('.//m:developer', nsmap)
            developers = []
            for dev in devs:
                dev_info = {}
                dev_id = dev.find('m:id', nsmap)
                if dev_id is not None:
                    dev_info['id'] = dev_id.text
                dev_name = dev.find('m:name', nsmap)
                if dev_name is not None:
                    dev_info['name'] = dev_name.text
                dev_email = dev.find('m:email', nsmap)
                if dev_email is not None:
                    dev_info['email'] = dev_email.text
                dev_url = dev.find('m:url', nsmap)
                if dev_url is not None:
                    dev_info['url'] = dev_url.text
                developers.append(dev_info)
            return developers
        except Exception as e:
            logging.warning("Failed to get author details for package %s: %s"%(pkg_name,str(e)))
            return None
    
    def get_downloads(self, pkg_name, pkg_info=None):
        pass
    
    def get_dependencies(self, pkg_name, ver_str=None, pkg_info=None, ver_info=None):
        try:
            namespace = {'m': 'http://maven.apache.org/POM/4.0.0'}

            root = self.get_metadata(pkg_name=pkg_name)
            dependencies = []
            for dependency in root.findall('.//m:dependency', namespace):
                group_id = dependency.find('m:groupId', namespace).text
                artifact_id = dependency.find('m:artifactId', namespace).text
                dependencies.append(f'{group_id}.{artifact_id}')
            
            if dependencies:
                return dependencies
            
            raise Exception('No dependencies found in metadata!')
        except Exception as e:
            logging.warning(str(e))
            return None

    def get_maintainers(self, pkg_name:str, ver_str:str=None, pkg_info:dict=None, ver_info:dict=None):
        pass
    
    def get_homepage(self, pkg_name, ver_str=None, pkg_info=None):
        pass
    
    def get_release_history(self, pkg_name, pkg_info=None, max_nums=-1):
        pass
    
    def get_readme(self, pkg_name, ver_str=None, pkg_info=None):
        pass