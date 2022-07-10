#
# Taken from MalOSS:  https://github.com/osssanitizer/maloss
#
import json
import logging
import os
import glob
from os.path import join, exists
import shutil
import tempfile
import dateutil.parser
import requests

from util.job_util import exec_command
from util.json_wrapper import json_loads
from pm_proxy.pm_base import PackageManagerProxy


class NpmjsProxy(PackageManagerProxy):
	# npm-scripts: How npm handles the "scripts" field
	# https://docs.npmjs.com/misc/scripts
	# default values:
	# server.js -> "start": "node server.js"
	# binding.gyp -> "install": "node-gyp rebuild"
	_BUILD_SCRIPTS = ('build',)
	_INSTALL_SCRIPTS = ('install', 'preinstall', 'postinstall')
	_UNINSTALL_SCRIPTS = ('uninstall', 'preuninstall', 'postuninstall')
	_TEST_SCRIPTS = ('test', 'pretest', 'posttest', 'test:browser', 'test:browserless')
	_PUBLISH_SCRIPTS = ('prepublish', 'prepare', 'prepublishOnly', 'prepack', 'postpack', 'publish', 'postpublish')
	_START_SCRIPTS = ('prestart', 'start', 'poststart')
	_STOP_SCRIPTS = ('prestop', 'stop', 'poststop')
	_RESTART_SCRIPTS = ('prerestart', 'restart', 'postrestart')
	_SHRINKWRAP_SCRIPTS = ('preshrinkwrap', 'shrinkwrap', 'postshrinkwrap')

	def __init__(self, registry=None, cache_dir=None, isolate_pkg_info=False):
		super(NpmjsProxy, self).__init__()
		self.registry = registry
		self.cache_dir = cache_dir
		self.isolate_pkg_info = isolate_pkg_info
		self.metadata_format = 'json'
		self.dep_format = 'json'
		self.name = 'npm'

	def _get_pkg_fname(self, pkg_name, pkg_version=None, suffix='tgz'):
		if pkg_name.startswith('@'):
			pkg_name = pkg_name.lstrip('@').replace('/', '-')
		if pkg_version is None:
			return '%s-*.%s' % (pkg_name, suffix)
		else:
			return '%s-%s.%s' % (pkg_name, pkg_version, suffix)

	def get_downloads(self, pkg_name, pkg_info):
		try:
			url = 'https://api.npmjs.org/downloads/point/last-week/' + pkg_name
			r = requests.get(url)
			r.raise_for_status()
			res = r.json()
			return int(res['downloads'])
		except Exception as e:
			logging.error("Error fetching downloads: %s" % (str(e)))
			return None

	def get_metadata(self, pkg_name, pkg_version=None):
		# fetch metadata from json api
		try:
			metadata_url = "https://registry.npmjs.org/%s" % (pkg_name)
			resp = requests.request('GET', metadata_url)
			resp.raise_for_status()
			pkg_info = resp.json()
			if pkg_info:
				try:
					pkg_name = pkg_info['name']
				except KeyError:
					pass
		except Exception as e:
			logging.error("fail in get_metadata for pkg %s: %s", pkg_name, str(e))
			pkg_info = None
		finally:
			return pkg_name, pkg_info

	def get_homepage(self, pkg_name, ver_str=None, pkg_info=None):
		if not pkg_info:
			pkg_info = self.get_metadata(pkg_name=pkg_name)
		assert pkg_info and isinstance(pkg_info, dict), "invalid metadata!"
		return pkg_info.get('homepage', None)

	def get_release_history(self, pkg_name, pkg_info=None, max_num=-1):
		from util.dates import datetime_delta, datetime_to_date_str
		if not pkg_info:
			pkg_info = self.get_metadata(pkg_name=pkg_name)
		assert pkg_info and 'time' in pkg_info, "package not found!"

		history = {}
		last_date = None
		for ver_str, ts in pkg_info['time'].items():
			if ver_str in ['modified', 'created']:
				continue

			try:
				date = dateutil.parser.parse(ts)
			except:
				date = None

			days = None
			if date and last_date:
				try:
					days = datetime_delta(date, date2=last_date, days=True)
				except:
					pass
			last_date = date

			history[ver_str] = {
				"release_date" : datetime_to_date_str(date),
				"days_since_last_release" : days
			}
		return history

	def get_version(self, pkg_name, ver_str=None, pkg_info=None):
		if not pkg_info:
			pkg_info = self.get_metadata(pkg_name=pkg_name)
		assert pkg_info and 'versions' in pkg_info, "package not found!"
		try:
			if not ver_str:
				ver_str = pkg_info['dist-tags']['latest']
			ver_info = pkg_info['versions'][ver_str]
		except KeyError:
			return None

		assert ver_info and 'version' in ver_info, "invalid version metadata!"
		try:
			ver_info['tag'] = ver_info['version']
		except KeyError:
			return None

		try:
			ver_info['uploaded'] = pkg_info['time'][ver_str]
		except KeyError:
			ver_info['uploaded'] = None

		try:
			ver_info['url'] = ver_info['dist']['tarball']
		except KeyError:
			ver_info['url'] = None

		return ver_info

	def get_repo(self, pkg_name, ver_str=None, pkg_info=None, ver_info=None):
		if not ver_info or 'repository' not in ver_info:
			if not pkg_info:
				pkg_info = self.get_metadata(pkg_name=pkg_name)
			assert pkg_info and 'versions' in pkg_info, "package not found!"
			ver_info = self.get_version(pkg_name, ver_str=ver_str, pkg_info=pkg_info)
		assert ver_info and 'repository' in ver_info, "invalid version metadata!"
		repo_info = ver_info['repository']
		if isinstance(repo_info, str):
			return repo_info
		elif isinstance(repo_info, dict) and 'url' in repo_info:
			return repo_info['url']
		raise Exception('invalid repo data')

	def get_dependencies(self, pkg_name, ver_str=None, pkg_info=None, ver_info=None):
		try:
			if not pkg_info:
				pkg_info = self.get_metadata(pkg_name=pkg_name)
			assert pkg_info and 'versions' in pkg_info, "invalid metadata!"
			if not ver_info:
				ver_info = self.get_version(pkg_name, ver_str=ver_str, pkg_info=pkg_info)
			assert ver_info and isinstance(ver_info, dict), "invalid ver metadata!"
			return ver_info.get('dependencies', None)
		except Exception as e:
			logging.debug("error parsing %s (%s) dependencies: %s" % (pkg_name, ver_str, str(e)))
			return None

	def get_description(self, pkg_name, ver_str=None, pkg_info=None):
		if not pkg_info:
			pkg_info = self.get_metadata(pkg_name=pkg_name)
		assert pkg_info and isinstance(pkg_info, dict), "invalid metadata!"
		return pkg_info.get('description', None)

	def get_readme(self, pkg_name, ver_str=None, pkg_info=None):
		if not pkg_info:
			pkg_info = self.get_metadata(pkg_name=pkg_name)
		assert pkg_info and isinstance(pkg_info, dict), "invalid metadata!"
		return pkg_info.get('readme', None)

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

	def get_maintainers(self, pkg_name:str, ver_str:str=None, pkg_info:dict=None, ver_info:dict=None):
		if not ver_info:
			if not pkg_info:
				pkg_info = self.get_metadata(pkg_name=pkg_name)
			assert pkg_info and 'versions' in pkg_info, "invalid metadata!"

			ver_info = self.get_version(pkg_name, ver_str=ver_str, pkg_info=pkg_info)
		assert ver_info, "invalid metadata!"

		maintainers = ver_info.get('maintainers', None)
		return self.__parse_dev_list(maintainers, 'maintainer')

	def get_author(self, pkg_name:str, ver_str:str=None, pkg_info:dict=None, ver_info:dict=None):
		if not ver_info:
			if not pkg_info:
				pkg_info = self.get_metadata(pkg_name=pkg_name)
			assert pkg_info and 'versions' in pkg_info, "invalid metadata!"

			ver_info = self.get_version(pkg_name, ver_str=ver_str, pkg_info=pkg_info)
		assert ver_info, "invalid metadata!"

		authors = ver_info.get('author', None)
		return self.__parse_dev_list(authors, 'authors')

		#users = ver_info.get('users', None)
		#data = self.__parse_dev_list(maintainers, 'user', data=data)

		#npm_user = ver_info.get('_npmUser', None)
		#data = self.__parse_dev_list(maintainers, '_npmUser', data=data)
