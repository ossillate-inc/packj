#
# Inspired from npmjs.py
#
import json
import logging
import os


from packj.audit.pm_proxy.pm_base import PackageManagerProxy

class LocalNodeProxy(PackageManagerProxy):
	def __init__(self, cache_dir=None, isolate_pkg_info=False):
		super(LocalNodeProxy, self).__init__()
		self.cache_dir = cache_dir
		self.isolate_pkg_info = isolate_pkg_info
		self.metadata_format = 'json'
		self.dep_format = 'json'
		self.name = 'local_node'

	def parse_deps_file(self, deps_file):
		try:
			with open(deps_file) as f:
				pkg_data = json.load(f)
			dep_list = []
			for pkg_name, ver_str in pkg_data['dependencies'].items():
				dep_list.append((pkg_name, ver_str.replace('^', '').replace('~', '')))
			return dep_list
		except Exception as e:
			logging.debug("Failed to parse NPM deps file %s: %s" % (line, str(e)))
			return None

	def get_downloads(self, pkg_name, pkg_info):
		return None

	def get_metadata(self, pkg_name, pkg_version=None):
		# local package, get metadata from package.json
		pkg_json_path = os.path.join(pkg_name, 'package.json')
		assert os.path.isdir(pkg_name) and os.path.isfile(pkg_json_path), 'invalid package path or package.json is not found'
		try:
			with open(os.path.join(pkg_name, 'package.json')) as f:
				pkg_info = json.load(f)
		except Exception as e:
			logging.debug("fail in get_metadata for pkg_path %s: %s (tips: package.json is needed)", pkg_name, str(e))
			pkg_info = None
		finally:
			return pkg_name, pkg_info

	def get_homepage(self, pkg_name, ver_str=None, pkg_info=None):
		try:
			return pkg_info['repository']['url']
		except KeyError:
			return None

	def get_release_history(self, pkg_name, pkg_info=None, max_num=-1):
		return None

	def get_version(self, pkg_name, ver_str=None, pkg_info=None):
		# local packages are no needed to be have versions attr
		try:
			ver_info = {'tag': pkg_info['version']}
		except KeyError:
			ver_info = {'tag': None}
		return ver_info

	def get_repo(self, pkg_name, ver_str=None, pkg_info=None, ver_info=None):
		if 'repository' in pkg_info and 'url' in pkg_info['repository']:
			return pkg_info['repository']['url']
		raise Exception('no repo url')

	def get_dependencies(self, pkg_name, ver_str=None, pkg_info=None, ver_info=None):
		try:
			return pkg_info['dependencies']
		except Exception as e:
			logging.debug("error parsing %s (%s) dependencies: %s" % (pkg_name, ver_str, str(e)))
			return None

	def get_description(self, pkg_name, ver_str=None, pkg_info=None):
		try:
			return pkg_info['description']
		except KeyError:
			return None

	def get_readme(self, pkg_name, ver_str=None, pkg_info=None):
		readme_path = os.path.join(pkg_name, 'README.md')
		if not os.path.isfile(readme_path):
			return None
		with open(readme_path, 'r') as f:
			return f.read()

	def get_author(self, pkg_name:str, ver_str:str=None, pkg_info:dict=None, ver_info:dict=None):
		try:
			# return author attribute in package.json
			return pkg_info['author']
		except KeyError:
			return None
