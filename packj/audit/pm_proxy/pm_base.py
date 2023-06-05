import json
import os
import re
import logging
import pickle
import datetime
import networkx
import itertools
from os.path import splitext, exists, join, basename
from packj.util.job_util import read_proto_from_file

class PackageManagerProxy(object):
	# TODO: add install failure handlers, i.e. what to do if a package is removed or fail to install
	# TODO: add get metadata failure handlers, i.e. what to do if a package is removed or info retrieval fails
	# TODO: add get dependency failure handlers, i.e. what to do if a package is removed or dep retrieval fails

	def __init__(self):
		# do nothing, but initialize placeholders for instance variables
		self.registry = None
		self.cache_dir = None
		self.isolate_pkg_info = False
		self.metadata_format = None
		self.dep_format = None
		self.name = 'pypi'

	def get_metadata(self, pkg_name, pkg_version=None):
		# load the metadata information for a package or get and cache it in cache_dir
		pass

	def get_versions(self, pkg_name, max_num=15, min_gap_days=30, with_time=False):
		# read the metadata and get (major) versions of the specified package
		pass

	def parse_deps_file(self, deps_file):
		# parse dependencies list in a file
		pass

	def get_author(self, pkg_name):
		# read the metadata and get author name and email of the specified package
		pass

	def get_version_hash(self, pkg_name, pkg_version, algorithm='sha1'):
		# get the hash of the package version
		pass

	@staticmethod
	def get_sanitized_pkgname(pkg_name):
		if not pkg_name:
			return pkg_name

		if '/' in pkg_name:
			pkg_name = pkg_name.replace('/', '..')
		invalid_name = re.compile(r'[^a-zA-Z0-9_.-]')
		pkg_name = re.sub(invalid_name, '..', pkg_name)
		return pkg_name

	@staticmethod
	def get_dir_for_pkgname(pkg_name, cache_dir):
		dir_for_pkgname = join(cache_dir, PackageManagerProxy.get_sanitized_pkgname(pkg_name))
		if not exists(dir_for_pkgname):
			os.makedirs(dir_for_pkgname)
		return dir_for_pkgname
     
     
	def get_pkg_info_dir(self, pkg_name):
		if self.isolate_pkg_info:
			return self.get_dir_for_pkgname(pkg_name=pkg_name, cache_dir=self.cache_dir)
		else:
			return self.cache_dir
