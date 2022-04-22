#!/usr/bin/env python
# -*- encoding: utf-8 -*-

from __future__ import generators

from abc import ABC, abstractmethod

class Package(ABC):
	_data = None
	_name = None
	_latest_version_str = None
	_created = None
	_descr = None
	_title = None

	_releases = None

	def __init__(self, metadata):
		self._data = metadata
		self._versions = {}
		self._pkg_url = None
		self._homepage = None

	def name(self):
		return self._name

	def descr(self):
		return self._descr

	def homepage(self):
		return self._homepage

	def pkg_url(self):
		return self._pkg_url

	def keywords(self):
		return self._keywords

	def releases(self):
		return self._releases

	def title(self):
		return self._title

	def latest_ver_str(self):
		return self._latest_version_str

	def dump(self):
		return {
			'name'		: self._name,
			'title'		: self._title,
			'created'	: self._created,
			'num_vers'	: self.num_versions(),
			'homepage'	: self._homepage,
			'pkg_url'	: self._pkg_url,
			'latest_ver_str': self._latest_version_str,
		}

	#################################################################
	# versions
	#################################################################
	def version_tags(self):
		return list(self._versions.keys())

	def num_versions(self):
		return len(self._versions)

	def versions(self):
		return self._versions.values()

	def version(self, ver_str):
		if version_id in self._versions:
			return self._versions[version_id]
		raise ValueError('Failed to find version %s' % (version_id))

	def latest_version_id(self):
		return self._latest_version_str

	def created(self):
		return self._created
