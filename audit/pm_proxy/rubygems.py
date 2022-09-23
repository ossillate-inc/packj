#
# Taken from MalOSS:  https://github.com/osssanitizer/maloss
#
import json
import logging
import re
import os
import inspect
import requests
import dateutil.parser
from os.path import exists, join

from util.job_util import exec_command
from audit.pm_proxy.pm_base import PackageManagerProxy

class RubygemsProxy(PackageManagerProxy):
	# Provide a standard and simplified way to build and package Ruby C and Java extensions using Rake as glue.
	# https://github.com/rake-compiler/rake-compiler
	def __init__(self, registry=None, cache_dir=None, isolate_pkg_info=False):
		super(RubygemsProxy, self).__init__()
		self.registry = registry
		self.cache_dir = cache_dir
		self.isolate_pkg_info = isolate_pkg_info
		self.metadata_format = 'json'
		self.dep_format = 'json'
		self.name = "rubygems"

	def _get_pkg_fname(self, pkg_name, pkg_version=None, suffix='gem'):
		# gem fetch the following gems: e.g. google-protobuf-3.7.0-x86_64-linux.gem, protobuf-3.10.0.gem
		if pkg_version is None:
			return '%s-*.%s' % (pkg_name, suffix)
		else:
			return '%s-%s*.%s' % (pkg_name, pkg_version, suffix)
		logging.debug("failed to download pkg %s ver %s", pkg_name, pkg_version)
		return None

	def __parse_string_for_dep_info(self, line):
		try:
			name_re = re.search(r"(.*)\(", line)
			assert name_re, "No name match found"
			name = name_re.group(0).replace('(', '')

			version_re = re.search(r"\((.*?)\)", line)
			assert version_re, "No version match found"
			version = version_re.group(0).replace('(', '').replace(')', '')

			return (name, version)
		except Exception as e:
			logging.debug("Failed to parse Gem dep %s: %s" % (line, str(e)))
			return None

	def parse_deps_file(self, deps_file):
		try:
			cwd = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
			cmd = ['ruby', 'parse_gemfile.rb', os.path.abspath(deps_file)]
			stdout, stderr, error = exec_command("parse deps", cmd, cwd=cwd, redirect_mask=3)
			if error or not stdout:
				logging.debug(f'deps parse error:\n{stdout}\n{stderr}')
				raise Exception(f'deps parse error {error}!')

			dep_list = []
			for line in stdout.split('\n'):
				line = line.replace(' ','')
				if line == '' or line.startswith('#'):
					continue
				dep = self.__parse_string_for_dep_info(line)
				if dep:
					dep_list.append(dep)
			return dep_list
		except Exception as e:
			logging.debug("Failed to parse RubyGems deps file %s: %s" % (deps_file, str(e)))
			return None

	def get_metadata(self, pkg_name, pkg_version=None):
		# rubygems API: https://guides.rubygems.org/rubygems-org-api/
		# e.g. curl https://rubygems.org/api/v1/gems/rails.json
		# e.g. curl https://rubygems.org/api/v1/versions/coulda.json
		# e.g. curl https://rubygems.org/api/v1/versions/rails/latest.json
		# use rubygems API to get metadata
		url = f'https://rubygems.org/api/v1/gems/{pkg_name}.json'
		try:
			resp = requests.request('GET', url)
			resp.raise_for_status()
			pkg_info = resp.json()
			if pkg_info:
				pkg_name = pkg_info.get('name', pkg_name)
		except Exception as e:
			logging.debug("Failed to get metadata for gem '%s' (version: %s): %s!" % \
					(pkg_name, pkg_version if pkg_version else 'latest', str(e)))
			pkg_info = None
		finally:
			return pkg_name, pkg_info

	def get_version(self, pkg_name, ver_str=None, pkg_info=None):
		if not pkg_info:
			pkg_info = self.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
		assert pkg_info and 'version' in pkg_info, "Invalid metadata!"
		if not ver_str:
			ver_str = pkg_info['version']
		ver_info = {
			'tag'	   : ver_str,
			'url'	   : pkg_info.get('gem_uri', None),
			'uploaded' : pkg_info.get('version_created_at', None),
			'digest'   : pkg_info.get('sha', None),
			'yanked'   : pkg_info.get('yanked', None),
		}
		return ver_info

	def get_description(self, pkg_name, ver_str=None, pkg_info=None):
		if not pkg_info:
			pkg_info = self.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
		assert pkg_info and 'version' in pkg_info, "Invalid metadata!"
		return pkg_info.get('info', None)

	def get_readme(self, pkg_name, ver_str=None, pkg_info=None):
		if not pkg_info:
			pkg_info = self.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
		assert pkg_info and 'version' in pkg_info, "Invalid metadata!"
		return pkg_info.get('documentation_uri')

	def get_release_history(self, pkg_name, pkg_info=None, max_num=-1):
		from util.dates import datetime_delta, datetime_to_date_str
		versions_url = f'https://rubygems.org/api/v1/versions/{pkg_name}.json'
		try:
			logging.debug("fetching versions info for %s" % (pkg_name))
			resp = requests.request('GET', versions_url)
			resp.raise_for_status()
			ver_list = resp.json()
		except Exception as e:
			logging.debug("Failed to get versions for rubygems package %s: %s!" % (pkg_name, str(e)))
			return None

		from util.dates import date_str_to_datetime
		ordered_data = sorted(ver_list,key=lambda x : date_str_to_datetime(x['created_at']))
		assert ordered_data, "Failed to sort release_history!"

		history = {}
		last_date = None
		for ver_data in ordered_data:
			try:
				ver_str = ver_data['number']
			except Exception as e:
				logging.warning('Failed to parse version data %s for rubygems package %s: %s' % \
					(ver_data, pkg_name, str(e)))
				continue

			downloads = ver_data.get('downloads_count', None)

			date = ver_data.get('created_at', None)
			if date:
				date = dateutil.parser.parse(date)

			days = None
			if date and last_date:
				try:
					days = datetime_delta(date, date2=last_date, days=True)
				except:
					pass
			last_date = date

			history[ver_str] = {
				"downloads"	   : downloads,
				"release_date" : datetime_to_date_str(date),
				"days_since_last_release" : days
			}
		return history

	def get_download_url(self, pkg_name, ver_str=None, pkg_info=None, ver_info=None):
		if not pkg_info:
			pkg_info = self.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
		assert pkg_info and 'version' in pkg_info, "Invalid metadata!"
		return pkg_info.get('gem_uri', None)

	def get_repo(self, pkg_name, ver_str=None, pkg_info=None, ver_info=None):
		if not pkg_info:
			pkg_info = self.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
		assert pkg_info and 'version' in pkg_info, "Invalid metadata!"
		return pkg_info.get('source_code_uri', None)

	def get_downloads(self, pkg_name, pkg_info):
		if not pkg_info:
			pkg_info = self.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
		assert pkg_info and 'version' in pkg_info, "Invalid metadata!"
		downloads = pkg_info.get('downloads', None)
		if downloads:
			return int(downloads)
		return None

	def get_homepage(self, pkg_name, ver_str=None, pkg_info=None):
		if not pkg_info:
			pkg_info = self.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
		assert pkg_info and 'version' in pkg_info, "Invalid metadata!"
		return pkg_info.get('homepage_uri', None)

	def get_versions(self, pkg_name, max_num=15, min_gap_days=30, with_time=False):
		# use rubygems API to get versions
		versions_url = f'https://rubygems.org/api/v1/versions/{pkg_name}.json'
		try:
			logging.debug("fetching versions info for %s" % (pkg_name))
			versions_content = requests.request('GET', versions_url)
			versions_info = json.loads(versions_content.text)
		except:
			logging.debug("fail in get_versions for pkg %s, ignoring!", pkg_name)
			return []
		# filter versions
		version_date = [(version_info['number'], dateutil.parser.parse(version_info['created_at']))
						for version_info in versions_info if 'created_at' in version_info]
		return self.filter_versions(version_date=version_date, max_num=max_num, min_gap_days=min_gap_days,
									with_time=with_time)

	def get_dependents(self,pkg_name, ver_str=None, pkg_info=None, ver_info=None):
		# use rubygems API to get reverse dependencies
		try:
			url = f'https://rubygems.org/api/v1/gems/{pkg_name}/reverse_dependencies.json'
			logging.debug("fetching reverse_dependencies for %s", pkg_name)
			resp = requests.request('GET', url)
			resp.raise_for_status()
			return resp.json()
		except Exception as e:
			logging.debug("Failed to get dependents for rubygems pkg %s: %s!" % (pkg_name, str(e)))
			return None

	# use rubygems API to get author profile
	def __owner_profile(self, uid):
		try:
			assert uid, "NULL user ID!"
			url = f'https://rubygems.org/api/v1/profiles/{uid}.json'
			logging.debug("Fetching profile for user %s" % (uid))
			resp = requests.request('GET', url)
			resp.raise_for_status()
			return resp.json()
		except Exception as e:
			logging.debug("Failed to fetch profile for user %s: %s!" % (uid, str(e)))
			return None

	# use rubygems API to get owners information
	def __owners(self, pkg_name):
		try:
			assert pkg_name, "NULL pkg name!"
			url = f'https://rubygems.org/api/v1/gems/{pkg_name}/owners.json'
			logging.debug("Fetching owners for package %s" % (pkg_name))
			resp = requests.request('GET', url)
			resp.raise_for_status()
			return resp.json()
		except Exception as e:
			logging.debug("Failed to fetch owners for package %s: %s!" % (pkg_name, str(e)))
			return None

		# use rubygems API to get num gems for this author
	def __num_gems(self, uid):
		try:
			assert uid, "NULL user ID!"
			url = f'https://rubygems.org/api/v1/owners/{uid}/gems.json'
			logging.debug("Fetching all gems for user %s" % (uid))
			resp = requests.request('GET', url)
			resp.raise_for_status()
			return resp.json()
		except Exception as e:
			logging.debug("Failed to fetch gems for user %s: %s!" % (pkg_name, str(e)))
			return None

	def __parse_dev_list(self, dev_list:str, dev_type:str, data=None):
		if not dev_list:
			return None
		elif isinstance(dev_list, list) and len(dev_list) and isinstance(dev_list[0], dict):
			pass
		elif isinstance(dev_list, dict):
			dev_list = [dev_list]
		elif isinstance(dev_list, str):
			dev_list = [{'name':name} for name in dev_list.split(',')]
		else:
			logging.debug("Failed to parse %s: invalid format!\n%s" % (dev_type, dev_list))
			return None
		if not data:
			data = []
		for dev in dev_list:
			if not isinstance(dev, dict):
				continue
			data.append({
				'name' : dev.get('name', None),
				'email' : dev.get('email', None),
				'id' : dev.get('id', None),
				'handle' : dev.get('handle', None),
			})

		if not len(data):
			return None
		return data

	def get_maintainers(self, pkg_name, ver_str=None, pkg_info=None, ver_info=None):
		if not pkg_info:
			pkg_info = self.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
		assert pkg_info and 'version' in pkg_info, "Invalid metadata!"

		owners = self.__owners(pkg_name)
		return self.__parse_dev_list(owners, 'maintainers')

	# use rubygems API to get num gems for this author
	def get_author(self, pkg_name, ver_str=None, pkg_info=None, ver_info=None):
		if not pkg_info:
			pkg_info = self.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
		assert pkg_info and 'version' in pkg_info, "Invalid metadata!"

		authors = pkg_info.get('authors', None)
		return self.__parse_dev_list(authors, 'authors')

	def get_dependencies(self, pkg_name, ver_str=None, pkg_info=None, ver_info=None):
		# Alternatively, use gem dependency, but it is regex-based and tricky to parse.
		if not pkg_info:
			pkg_info = self.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
		assert pkg_info and 'version' in pkg_info, "Invalid metadata!"

		if 'dependencies' in pkg_info and 'runtime' in pkg_info['dependencies']:
			pkg_info_deps = pkg_info['dependencies']['runtime']
			if pkg_info_deps:
				return [dep_info['name'] for dep_info in pkg_info_deps]
		return None
