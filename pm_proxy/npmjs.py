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

	def download(self, pkg_name, pkg_version=None, outdir=None, binary=False, with_dep=False):
		if pkg_version:
			download_cmd = ['npm', 'pack', '%s@%s' % (pkg_name, pkg_version)]
		else:
			download_cmd = ['npm', 'pack', pkg_name]
		# Node.js tool for easy binary deployment of C++ addons
		# https://github.com/mapbox/node-pre-gyp/
		if binary:
			logging.warning("support for binary downloading is not added yet!")
		# npm pack with dependencies
		# https://github.com/npm/npm/issues/4210
		if with_dep:
			logging.warning("support for packing dependencies is not added yet!")
		exec_command('npm pack', download_cmd, cwd=outdir)
		download_path = join(outdir, self._get_pkg_fname(pkg_name=pkg_name, pkg_version=pkg_version))
		if pkg_version is None:
			download_paths = glob.glob(download_path)
			if len(download_paths) == 1:
				return download_paths[0]
		else:
			if exists(download_path):
				return download_path
		logging.error("failed to download pkg %s ver %s", pkg_name, pkg_version)
		return None

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

	def _install_init(self, install_dir):
		# run npm init to initialize repo
		npm_init_cmd = ['npm', 'init', '-y']
		exec_command('npm init', npm_init_cmd, cwd=install_dir)

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
		assert pkg_info and 'homepage' in pkg_info, "invalid package metadata!"
		return pkg_info['homepage']

	def get_version(self, pkg_name, ver_str=None, pkg_info=None):
		if not pkg_info:
			pkg_info = self.get_metadata(pkg_name=pkg_name)
		assert pkg_info and 'versions' in pkg_info, "invalid package metadata!"
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
			assert pkg_info and 'ho' in pkg_info, "invalid package metadata!"
		assert ver_info and 'repository' in ver_info, "invalid version metadata!"
		repo_info = ver_info['repository']
		if isinstance(repo_info, str):
			return repo_info
		elif isinstance(repo_info, dict) and 'url' in repo_info:
			return repo_info['url']
		raise Exception('invalid repo data')

	def get_description(self, pkg_name, ver_str=None, pkg_info=None):
		if not pkg_info:
			pkg_info = self.get_metadata(pkg_name=pkg_name)
		assert pkg_info and 'readme' in pkg_info, "invalid metadata!"
		return pkg_info['readme']

	def get_versions(self, pkg_name, max_num=15, min_gap_days=30, with_time=False):
		pkg_info = self.get_metadata(pkg_name=pkg_name)
		assert pkg_info and 'time' in pkg_info, "invalid metadata!"
		try:
			version_date = [(ver, dateutil.parser.parse(ts)) for ver, ts in pkg_info['time'].items()
							if ver not in ('modified', 'created')]
		except Exception as e:
			logging.error("error parsing timestamps in %s", pkg_info['time'])
			return []
		return self.filter_versions(version_date=version_date, max_num=max_num, min_gap_days=min_gap_days,
									with_time=with_time)

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

	def get_dep(self, pkg_name, pkg_version=None, flatten=False, cache_only=False):
		super(NpmjsProxy, self).get_dep(pkg_name=pkg_name, pkg_version=pkg_version, flatten=flatten,
										cache_only=cache_only)
		# load cached dependency information
		pkg_info_dir = self.get_pkg_info_dir(pkg_name=pkg_name)
		if pkg_info_dir is not None:
			if flatten:
				dep_fname = self.get_flatten_dep_fname(pkg_name=pkg_name, pkg_version=pkg_version, fmt=self.dep_format)
			else:
				dep_fname = self.get_dep_fname(pkg_name=pkg_name, pkg_version=pkg_version, fmt=self.dep_format)
			dep_file = join(pkg_info_dir, dep_fname)
			if exists(dep_file):
				logging.warning("get_dep: using cached dep_file %s!", dep_file)
				if self.dep_format == 'json':
					try:
						return json.load(open(dep_file, 'r'))
					except:
						logging.debug("fail to load dep_file: %s, regenerating!", dep_file)
				else:
					logging.error("get_dep: output format %s is not supported!", self.dep_format)
					return None
		if cache_only:
			return None
		# use npm install to get the dependencies
		temp_install_dir = tempfile.mkdtemp(prefix='get_dep-')
		self.install(pkg_name=pkg_name, pkg_version=pkg_version, install_dir=temp_install_dir)
		shrinkwrap_cmd = ['npm', 'shrinkwrap']
		exec_command('npm shrinkwrap', shrinkwrap_cmd, cwd=temp_install_dir)
		# FIXME: seems that package-lock.json is not always available
		temp_npm_shrinkwrap = join(temp_install_dir, 'npm-shrinkwrap.json')
		dep_pkgs = {}
		flatten_dep_pkgs = {}
		if not exists(temp_npm_shrinkwrap):
			logging.error("fail to get dependency for %s", pkg_name)
		else:
			try:
				npm_shrinkwrap_info = json.load(open(temp_npm_shrinkwrap, 'r'))
				if 'dependencies' in npm_shrinkwrap_info and pkg_name in npm_shrinkwrap_info['dependencies']:
					flatten_dep_pkgs = {dep_name: dep_info['version'] for dep_name, dep_info
										in npm_shrinkwrap_info['dependencies'].items() if dep_name != pkg_name}
					if 'requires' in npm_shrinkwrap_info['dependencies'][pkg_name]:
						dep_pkg_names = npm_shrinkwrap_info['dependencies'][pkg_name]['requires'].keys()
						dep_pkgs = {dep_name: dep_version for dep_name, dep_version in flatten_dep_pkgs.items()
									if dep_name in dep_pkg_names}
				else:
					logging.error("no dependency including self is found for %s, info: %s", pkg_name, npm_shrinkwrap_info)
			except Exception as e:
				logging.error("failed while getting dependencies (%s) for pkg %s: %s!", flatten_dep_pkgs, pkg_name, str(e))
		logging.warning("%s has %d deps and %d flatten deps", pkg_name, len(dep_pkgs), len(flatten_dep_pkgs))
		if pkg_info_dir is not None:
			if not exists(pkg_info_dir):
				os.makedirs(pkg_info_dir)
			dep_fname = self.get_dep_fname(pkg_name=pkg_name, pkg_version=pkg_version, fmt=self.dep_format)
			dep_file = join(pkg_info_dir, dep_fname)
			flatten_dep_fname = self.get_flatten_dep_fname(pkg_name=pkg_name, pkg_version=pkg_version, fmt=self.dep_format)
			flatten_dep_file = join(pkg_info_dir, flatten_dep_fname)
			if self.dep_format == 'json':
				json.dump(dep_pkgs, open(dep_file, 'w'), indent=2)
				json.dump(flatten_dep_pkgs, open(flatten_dep_file, 'w'), indent=2)
			else:
				logging.error("get_dep: output format %s is not supported!", self.dep_format)
		# remove the installation directory
		shutil.rmtree(temp_install_dir)
		return flatten_dep_pkgs if flatten else dep_pkgs
