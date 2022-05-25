#
# Taken from MalOSS:  https://github.com/osssanitizer/maloss
#
import json
import logging
import os
import requests
import dateutil.parser
from os.path import join, exists

from util.json_wrapper import json_loads
from pm_proxy.pm_base import PackageManagerProxy

class PypiProxy(PackageManagerProxy):
	# Build python extensions
	# https://docs.python.org/2/distutils/configfile.html
	# https://docs.python.org/3/distutils/setupscript.html
	# Python packaging recommendations: pyenv + setuptools + bdist_wheel + twine
	# https://packaging.python.org/guides/tool-recommendations/
	# Glossory
	# https://packaging.python.org/glossary/#term-wheel
	# All comparisons of distribution names MUST be case insensitive, and MUST consider hyphens and underscores to be equivalent.
	# https://stackoverflow.com/questions/26503509/is-pypi-case-sensitive
	def __init__(self, registry=None, cache_dir=None, isolate_pkg_info=False):
		super(PypiProxy, self).__init__()
		self.registry = registry
		self.cache_dir = cache_dir
		self.isolate_pkg_info = isolate_pkg_info
		self.metadata_format = 'json'
		self.dep_format = 'requirement'
		self._query_cache = {}

	def get_metadata(self, pkg_name, pkg_version=None):
		# PyPI json api
		# https://wiki.python.org/moin/PyPIJSON
		# json api for latest version: http://pypi.python.org/pypi/<package_name>/json
		# json api for a particular version: http://pypi.python.org/pypi/<package_name>/<version>/json
		# load cached metadata information
		pkg_info_dir = self.get_pkg_info_dir(pkg_name=pkg_name)
		if pkg_info_dir is not None:
			metadata_fname = self.get_metadata_fname(pkg_name=pkg_name, pkg_version=pkg_version, fmt=self.metadata_format)
			metadata_file = join(pkg_info_dir, metadata_fname)
			if exists(metadata_file):
				logging.warning("get_metadata: using cached metadata_file %s!", metadata_file)
				if self.metadata_format == 'json':
					try:
						return json.load(open(metadata_file, 'r'))
					except:
						logging.debug("fail to load metadata_file: %s, regenerating!", metadata_file)
				else:
					logging.error("get_metadata: output format %s is not supported!", self.metadata_format)
					return None
		# fetch metadata from json api
		if pkg_version:
			metadata_url = "https://pypi.python.org/pypi/%s/%s/json" % (pkg_name, pkg_version)
		else:
			metadata_url = "https://pypi.python.org/pypi/%s/json" % pkg_name
		try:
			metadata_content = requests.request('GET', metadata_url)
			pkg_info = json_loads(metadata_content.text)
		except Exception as e:
			logging.debug("fail in get_metadata for pkg %s, ignoring!\n%s", pkg_name, str(e))
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

	def get_release_history(self, pkg_name, pkg_info=None, max_num=-1):
		from util.dates import datetime_delta, datetime_to_date_str
		if not pkg_info:
			pkg_info = self.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
		assert pkg_info and 'info' in pkg_info, "Failed to fetch metadata!"
		# skip versions that don't have a distribution
		ver_dists = [(ver, dists) for ver, dists in pkg_info['releases'].items() if len(dists) > 0]

		history = {}
		last_date = None
		for ver_str, dists in ver_dists:
			try:
				date = sorted([dateutil.parser.parse(dist['upload_time']) for dist in dists], reverse=True)[0]
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
			pkg_info = self.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
		assert pkg_info and 'info' in pkg_info, "Failed to fetch metadata!"
		if not ver_str:
			ver_str = pkg_info['info']['version']
		if 'releases' in pkg_info and ver_str in pkg_info['releases']:
			for dist in pkg_info['releases'][ver_str]:
				if dist['packagetype'] == 'sdist':
					return {'tag':ver_str, 'url':dist['url'], 'type':'sdist', 'uploaded':dist['upload_time']}
			for dist in pkg_info['releases'][ver_str]:
				if dist['packagetype'] == 'bdist_wheel':
					return {'tag':ver_str, 'type':'bdist_wheel', 'url':dist['url'], 'uploaded':dist['upload_time']}
		return None

	def get_description(self, pkg_name, ver_str=None, pkg_info=None):
		try:
			if not pkg_info:
				pkg_info = self.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
			assert pkg_info and 'info' in pkg_info, "Failed to fetch metadata!"
			return pkg_info['info']['description']
		except Exception as e:
			logging.error(str(e))
			return None

	def get_dependencies(self, pkg_name, ver_str=None, pkg_info=None, ver_info=None):
		try:
			if not pkg_info:
				pkg_info = self.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
			assert pkg_info and 'info' in pkg_info, "Failed to fetch metadata!"
			return pkg_info['info']['requires_dist']
		except KeyError:
			return None
		except Exception as e:
			logging.error(str(e))
			return None

	def get_download_url(self, pkg_name, ver_str=None, pkg_info=None, ver_info=None):
		try:
			if not pkg_info:
				pkg_info = self.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
			assert pkg_info and 'info' in pkg_info, "Failed to fetch metadata!"
			try:
				info = pkg_info['info']
				if info and info['project_urls']:
					return info['project_urls']['Download']
				return None
			except KeyError:
				return None
		except Exception as e:
			logging.error(str(e))
			return None

	def get_repo(self, pkg_name, ver_str=None, pkg_info=None, ver_info=None):
		try:
			if not pkg_info:
				pkg_info = self.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
			assert pkg_info and 'info' in pkg_info, "Failed to fetch metadata!"
			try:
				info = pkg_info['info']
				if info and info['project_urls']:
					return info['project_urls']['Source']
				return None
			except KeyError:
				return None
		except Exception as e:
			logging.error(str(e))
			return None

	def get_downloads(self, pkg_name):
		try:
			BASE_URL = "https://pypistats.org/api/"
			USER_AGENT = "pypistats/0.11.0"
			endpoint = "packages/" + pkg_name + "/recent"
			url = BASE_URL + endpoint.lower()
			r = requests.get(url, headers={"User-Agent": USER_AGENT})
			r.raise_for_status()
			res = r.json()
			return int(res["data"]["last_week"])
		except Exception as e:
			logging.error("Error fetching downloads: %s" % (str(e)))
			return None

	def get_homepage(self, pkg_name, ver_str=None, pkg_info=None):
		try:
			if not pkg_info:
				pkg_info = self.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
			assert pkg_info and 'info' in pkg_info, "Failed to fetch metadata!"
			return pkg_info['info']['home_page']
		except Exception as e:
			logging.error(str(e))
			return None

	def get_author(self, pkg_name, ver_str=None, pkg_info=None, ver_info=None):
		try:
			if not pkg_info:
				pkg_info = self.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
			assert pkg_info and 'info' in pkg_info, "Failed to fetch metadata!"
			maintainer = pkg_info['info'].get('maintainer', None)
			author = pkg_info['info'].get('author', None)
			author_email = pkg_info['info'].get('author_email', None)
			return {'maintainer': maintainer, 'author': author, 'email': author_email}
		except Exception as e:
			logging.error(str(e))
			return None
