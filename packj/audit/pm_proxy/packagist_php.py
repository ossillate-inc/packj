import requests
import logging
import dateutil.parser

from packj.audit.pm_proxy.pm_base import PackageManagerProxy

class PackagistProxy(PackageManagerProxy):
    def __init__(self, registry=None, cache_dir=None, isolated_pkg_info=False):
        super(PackagistProxy, self).__init__()
        self.registry = registry
        self.cache_dir = cache_dir
        self.isolate_pkg_info = isolated_pkg_info
        self.metadata_format = 'json'
        self.dep_format = 'json'
        self.name = 'packagist'
    def get_metadata(self, pkg_name, pkg_version=None):
        # PHP's Package managers --> https://packagist.org/
        # Json API for a particular package: https://packagist.org/packages/[vendor]/[package].json
        
        metadata_url = f'https://packagist.org/packages/{pkg_name}.json'
        
        try:
            resp = requests.request('GET', metadata_url)
            resp.raise_for_status()
            pkg_info = resp.json()
            if pkg_info:
                try:
                    pkg_name = pkg_info['package']['name']
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
        assert pkg_info and 'package' in pkg_info, "Failed to fetch metadata!"
        
        if not ver_str:
            vers_info = pkg_info['package']['versions']
            for key,_ in vers_info.items():
                if key.find(".")>=0:
                    ver_str=key
                    break
        version_info = pkg_info['package']['versions'][ver_str]
        if version_info:
            tag = ver_str
            url = version_info['dist']['url']
            uploaded = version_info['time']
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
        try:
            if not pkg_info:
                _, pkg_info = self.get_metadata(pkg_name=pkg_name)
            assert pkg_info and 'package' in pkg_info, "Failed to fetch metadata!"
            
            return int(pkg_info['package']['downloads']['total'])
        except Exception as e:
            logging.warning("Error fetching downloads: %s"%str(e))
            return None
    def get_description(self, pkg_name, ver_str=None, pkg_info=None):
        try:
            if not pkg_info:
                _, pkg_info = self.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
            assert pkg_info and 'package' in pkg_info, "Failed to fetch metadata!"
            
            description = pkg_info['package']['description']
            if description and len(description):
                return description
            
            raise Exception(' No description found in metadata!')
        except Exception as e:
            logging.warning(str(e))
            return None
    def get_repo(self, pkg_name, ver_str=None, pkg_info=None, ver_info=None):
        try:
            if not pkg_info:
                _, pkg_info = self.get_metadata(pkg_name=pkg_name)
            assert pkg_info and 'package' in pkg_info, "Failed to fetch metadata!"
            
            if 'package' in pkg_info:
                return pkg_info['package']['repository']
            
            raise Exception('No repository found in metadata!')
        except Exception as e:
            logging.warning(str(e))
            return None
    def __parse_dev_list(self, dev_list:str, dev_type:str, data=None):
        if not dev_list:
            return None
        elif isinstance(dev_list, list) and len(dev_list) and isinstance(dev_list[0], dict):
            pass
        elif isinstance(dev_list, dict):
            dev_list = [dev_list]
        elif isinstance(dev_list, str) and ',' in dev_list:
            dev_list = dev_list.split(',')
        else:
            logging("Failed to parse %s: invalid format!\n%s" % (dev_type, dev_list))
            return None
        if not data:
            data = []
        for dev in dev_list:
            if not isinstance(dev, dict):
                continue
            data.append({
				'name' : dev.get('name', None),
				'email' : dev.get('email', None),
			})
        if not len(data):
            return None
        return data
    def get_author(self, pkg_name, ver_str=None, pkg_info=None, ver_info=None):
        try:
            if not pkg_info:
                _, pkg_info = self.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
            assert pkg_info and 'package' in pkg_info, "Failed to fetch metadata!"
        
            if not ver_str:
                ver_info = pkg_info['package']['versions']
                for key,_ in ver_info.items():
                    if key.find(".")>=0:
                        ver_str=key
                        break
                ver_info = pkg_info['package']['versions'][ver_str]
            if ver_str:
                ver_info = pkg_info['package']['versions'][ver_str]
            
            author_info = ver_info['authors'][0]
            return [{'name':author_info.get('name',None),'email':author_info.get('email',None),'url':author_info.get('url',None)}]
        except Exception as e:
            logging.warning("Failed to get author details for package %s: %s"%(pkg_name,str(e)))
            return None
    def get_maintainers(self, pkg_name:str, ver_str:str=None, pkg_info:dict=None, ver_info:dict=None):
        if not pkg_info:
            _, pkg_info = self.get_metadata(pkg_name=pkg_name)
        assert pkg_info and 'package' in pkg_info, "Failed to fetch metadata!"
        
        
        maintainers = pkg_info['package']['maintainers']
        return self.__parse_dev_list(maintainers, 'maintainer')
    def get_homepage(self, pkg_name, ver_str=None, pkg_info=None):
        try:
            if not pkg_info:
                _, pkg_info = self.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
            assert pkg_info and 'description' in pkg_info, "Failed to fetch metadata!"
            
            if not ver_str:
                vers_info = pkg_info['package']['versions']
                for key,_ in vers_info.items():
                    if key.find(".")>=0:
                        ver_str=key
                        break
            version_info = pkg_info['package']['versions'][ver_str]
            
            homepage = version_info['homepage']
            if homepage:
                return homepage
            
            raise Exception("No homepage url in metadata!")
        except Exception as e:
            logging.warning(str(e))
            return None
    def get_dependencies(self, pkg_name, ver_str=None, pkg_info=None, ver_info=None):
        try:
            if not ver_info:
                if not pkg_info:
                    _, pkg_info = self.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
                assert pkg_info and 'package' in pkg_info, "Failed to fetch metadata!"
            
                if not ver_str:
                    ver_info = pkg_info['package']['versions']
                    for key,_ in ver_info.items():
                        if key.find(".")>=0:
                            ver_str=key
                            break
                    ver_info = pkg_info['package']['versions'][ver_str]
                if ver_str:
                    ver_info = pkg_info['package']['versions'][ver_str]
                
                dep_dict = ver_info['require']
                dep_list=[]
                for key,_ in dep_dict:
                    dep_list.append(key)
                if dep_list:
                    return dep_list
                raise Exception('No dependencies found in metadata!')
        except Exception as e:
            logging.warning(str(e))
            return None
    def get_release_history(self, pkg_name, pkg_info=None, max_nums=-1):
        from packj.util.dates import datetime_delta, datetime_to_date_str
        
        _, pkg_info =self.get_metadata(pkg_name=pkg_name)
        assert pkg_info and 'package' in pkg_info, "Failed to fetch metadata!"
        
        assert 'versions' in pkg_info['package'] and pkg_info['package'], "No release info found!"
        vers_info=pkg_info['package']['versions']
        ver_dists=[]
        for key,val in vers_info.items():
                if key.find(".")>=0 and len(val)>0:
                    ver_dists.append((key,val))
        
        history = {}
        last_date = None
        for ver_str, dists in ver_dists:
            try:
                date = dateutil.parser.parse(dists['time'])
            except:
                date = None
            days = None
            if date or last_date:
                try:
                    days = datetime_delta(date, date2=last_date, days=True)
                except:
                    pass
            last_date = date
            
            history[ver_str] = {
                'release_date':datetime_to_date_str(date),
                'days_since_last_release': days,
                'yanked': False,
            }
        return history
    def get_readme(self, pkg_name, ver_str=None, pkg_info=None):
        pass