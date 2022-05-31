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

	def _get_pkg_fname(self, pkg_name, pkg_version=None, suffix='tgz'):
		if pkg_name.startswith('@'):
			pkg_name = pkg_name.lstrip('@').replace('/', '-')
		if pkg_version is None:
			return '%s-*.%s' % (pkg_name, suffix)
		else:
			return '%s-%s.%s' % (pkg_name, pkg_version, suffix)

	def get_downloads(self, pkg_name):
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
						pkg_info = json.load(open(metadata_file, 'r'))
						if (len(pkg_info) == 1 and "error" in pkg_info and pkg_info["error"]["summary"] ==
								"getaddrinfo ENOTFOUND registry.npmjs.us registry.npmjs.us:443"):
							logging.error("previous fetch of metadata failed, regenerating!")
						else:
							return pkg_info
					except:
						logging.debug("fail to load metadata_file: %s, regenerating!", metadata_file)
				else:
					logging.error("get_metadata: output format %s is not supported!", self.metadata_format)
					return None
		# fetch metadata from json api
		try:
			metadata_url = "https://registry.npmjs.org/%s" % (pkg_name)
			metadata_content = requests.request('GET', metadata_url)
			pkg_info = json_loads(metadata_content.text)
		except Exception as e:
			logging.error("fail in get_metadata for pkg %s: %s", pkg_name, str(e))
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

	def get_homepage(self, pkg_name, ver_str=None, pkg_info=None):
		if not pkg_info:
			pkg_info = self.get_metadata(pkg_name=pkg_name)
		assert pkg_info and 'homepage' in pkg_info, "package not found!"
		return pkg_info['homepage']

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
			assert ver_info, "invalid metadata!"
			return ver_info['dependencies']
		except Exception as e:
			logging.debug("error parsing %s (%s) dependencies: %s" % (pkg_name, ver_str, str(e)))
			return None

	def get_description(self, pkg_name, ver_str=None, pkg_info=None):
		if not pkg_info:
			pkg_info = self.get_metadata(pkg_name=pkg_name)
		assert pkg_info and 'readme' in pkg_info, "invalid metadata!"
		return pkg_info['readme']

	def get_author(self, pkg_name, ver_str=None, pkg_info=None, ver_info=None, typ='author'):
		if not ver_info:
			pkg_info = self.get_metadata(pkg_name=pkg_name)
			if pkg_info is None or 'time' not in pkg_info:
				return {}
		if typ == 'author':
			return ver_info.get('author', None)
		elif typ == 'maintainers':
			return pkg_info.get('maintainers', None)
		elif typ == 'users':
			return pkg_info.get('users', None)
		elif typ == 'npmUser':
			pkg_info.get('_npmUser', None)
		raise Exception("Invalid dev type %s" % (typ))
