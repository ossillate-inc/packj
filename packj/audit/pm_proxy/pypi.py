#
# Taken from MalOSS:  https://github.com/osssanitizer/maloss
#
import json
import logging
import re
import os
import requests
import dateutil.parser
from os.path import join, exists

from packj.util.files import read_file_lines
from packj.util.json_wrapper import json_loads
from packj.audit.pm_proxy.pm_base import PackageManagerProxy

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
		# fetch metadata from json api
		if pkg_version:
			metadata_url = f'https://pypi.python.org/pypi/{pkg_name}/{pkg_version}/json'
		else:
			metadata_url = f'https://pypi.python.org/pypi/{pkg_name}/json'

		try:
			resp = requests.request('GET', metadata_url)
			resp.raise_for_status()
			pkg_info = resp.json()
			if pkg_info:
				try:
					pkg_name = pkg_info['info']['name']
				except KeyError:
					pass
		except Exception as e:
			logging.debug("fail in get_metadata for pkg %s, ignoring!\n%s", pkg_name, str(e))
			pkg_info = None
		finally:
			return pkg_name, pkg_info

	def __parse_string_for_dep_info(self, line):
		try:
			ver_match = re.search(r'(.*)(==|>=|<=)(.*)', line)
			if ver_match is not None:
				return ver_match.group(1), ver_match.group(3)
			else:
				return (line, None)
		except Exception as e:
			logging.debug("Failed to parse PyPI dep %s: %s" % (line, str(e)))
			return None

	def parse_deps_file(self, deps_file):
		try:
			dep_list = []
			for line in read_file_lines(deps_file):
				line = line.replace(' ','')
				if line == '' or line.startswith('#'):
					continue
				dep = self.__parse_string_for_dep_info(line)
				assert dep, "failed"

				dep_list.append(dep)
			return dep_list
		except Exception as e:
			logging.debug("Failed to parse PyPI deps file %s: %s" % (line, str(e)))
			return None

	def get_release_history(self, pkg_name, pkg_info=None, max_num=-1):
		from packj.util.dates import datetime_delta, datetime_to_date_str
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

			try:
				yanked = dists[0]['yanked']
			except:
				yanked = None

			history[ver_str] = {
				"release_date"				: datetime_to_date_str(date),
				"days_since_last_release"	: days,
				"yanked"					: yanked,
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
		elif 'urls' in pkg_info and pkg_info['urls']:
				for dist in pkg_info['urls']:
						if dist['packagetype'] == 'sdist':
								return {'tag':ver_str, 'url':dist['url'], 'type':'sdist', 'uploaded':dist['upload_time']}
				for dist in pkg_info['urls']:
						if dist['packagetype'] == 'bdist_wheel':
								return {'tag':ver_str, 'type':'bdist_wheel', 'url':dist['url'], 'uploaded':dist['upload_time']}
		return None

	def get_description(self, pkg_name, ver_str=None, pkg_info=None):
		try:
			if not pkg_info:
				pkg_info = self.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
			assert pkg_info, "Failed to fetch metadata!"

			info = pkg_info.get('info', None)
			assert info, "Invalid metadata!"

			summary = info.get('summary', None)
			if summary: return summary

			descr = info.get('description', None)
			if descr and len(descr) < 100: return descr

			raise Exception('No package summary or description found in metadata')
		except Exception as e:
			logging.warning(str(e))
			return None

	def get_readme(self, pkg_name, ver_str=None, pkg_info=None):
		try:
			if not pkg_info:
				pkg_info = self.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
			assert pkg_info, "Failed to fetch metadata!"

			info = pkg_info.get('info', None)
			assert info, "Invalid metadata!"

			descr = info.get('description', None)
			if descr: return descr

			raise Exception('No package description found in metadata')
		except Exception as e:
			logging.warning(str(e))
			return None

	def get_dependencies(self, pkg_name, ver_str=None, pkg_info=None, ver_info=None):
		try:
			if not pkg_info:
				pkg_info = self.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
			assert pkg_info, "Failed to fetch metadata!"

			info = pkg_info.get('info', None)
			assert info, "Invalid metadata!"

			deps = info.get('requires_dist', None)
			if deps: return deps

			raise Exception('No dependency info found in metadata')
		except Exception as e:
			logging.warning(str(e))
			return None

	def get_download_url(self, pkg_name, ver_str=None, pkg_info=None, ver_info=None):
		try:
			if not pkg_info:
				pkg_info = self.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
			assert pkg_info, "Failed to fetch metadata!"

			info = pkg_info.get('info', None)
			assert info, "Invalid metadata!"

			proj_urls = info.get('project_urls', None)
			assert proj_urls, "No project URLs!"

			download = proj_urls.get('Download', None)
			if download: return download

			raise Exception('No download info found in metadata')
		except Exception as e:
			logging.warning(str(e))
			return None

	def get_repo(self, pkg_name, ver_str=None, pkg_info=None, ver_info=None):
		try:
			if not pkg_info:
				pkg_info = self.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
			assert pkg_info, "Failed to fetch metadata!"

			info = pkg_info.get('info', None)
			assert info, "Invalid metadata!"

			proj_urls = info.get('project_urls', None)
			assert proj_urls, "No project URLs!"

			src = proj_urls.get('Source', None)
			if src: return src

			src = proj_urls.get('source', None)
			if src: return src

			repo = proj_urls.get('repository', None)
			if repo: return repo

			repo = proj_urls.get('Repository', None)
			if repo: return repo

			raise Exception('No repo info found in metadata')
		except Exception as e:
			logging.warning(str(e))
			return None

	def get_downloads(self, pkg_name, pkg_info):
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
			logging.warning("Error fetching downloads: %s" % (str(e)))
			return None

	def get_homepage(self, pkg_name, ver_str=None, pkg_info=None):
		try:
			if not pkg_info:
				pkg_info = self.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
			assert pkg_info, "Failed to fetch metadata!"

			info = pkg_info.get('info', None)
			assert info, "Invalid metadata!"

			homepage = info.get('home_page', None)
			if homepage: return homepage

			proj_urls = info.get('project_urls', None)
			assert proj_urls, "No project URLs!"

			homepage = proj_urls.get('Homepage', None)
			if homepage: return homepage

			homepage = proj_urls.get('homepage', None)
			if homepage: return homepage

			raise Exception('No homepage info found in metadata')
		except Exception as e:
			logging.warning(str(e))
			return None

	def __get_email_list(self, data):
		data = data.replace(' ','')
		if isinstance(data, list):
			return data
		elif isinstance(data, str):
			if ',' in data:
				return data.split(',')
			elif ' ' in data:
				return data.split(' ')
			elif ';' in data:
				return data.split(';')
			else:
				return [data]
		else:
			raise Exception('error parsing author email!')

	def get_maintainers(self, pkg_name, ver_str=None, pkg_info=None, ver_info=None):
		try:
			if not pkg_info:
				pkg_info = self.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
			assert pkg_info and 'info' in pkg_info, "Failed to fetch metadata!"

			maintainer = pkg_info['info'].get('maintainer', None)
			maintainer_email = pkg_info['info'].get('maintainer_email', None)
			if not maintainer_email or maintainer_email == '':
				return None

			email_list = self.__get_email_list(maintainer_email)
			if not email_list:
				return None

			ret = []
			for email in email_list:
				ret.append({'email' : email})
			return ret
		except Exception as e:
			logging.warning("Failed to get maintainers for PyPI package %s: %s" % (pkg_name, str(e)))
			return None

	def get_author(self, pkg_name, ver_str=None, pkg_info=None, ver_info=None):
		try:
			if not pkg_info:
				pkg_info = self.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
			assert pkg_info and 'info' in pkg_info, "Failed to fetch metadata!"

			author = pkg_info['info'].get('author', None)
			author_email = pkg_info['info'].get('author_email', None)

			if not author_email or author_email == '':
				maintainer_email = pkg_info['info'].get('maintainer_email', None)
				if not maintainer_email or maintainer_email == '':
					return None
				email_list = self.__get_email_list(maintainer_email)
			else:
				email_list = self.__get_email_list(author_email)
			if not email_list:
				return None

			ret = []
			for email in email_list:
				ret.append({'email' : email})
			return ret
		except Exception as e:
			logging.warning("Failed to get author for PyPI package %s: %s" % (pkg_name, str(e)))
			return None
