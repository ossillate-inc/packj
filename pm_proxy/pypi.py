import json
import logging
import os
import glob
import shutil
import tempfile
import requests
import pkg_resources
import dateutil.parser
from os.path import join, exists
from email.parser import HeaderParser

from util.job_util import exec_command
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

	def _get_py_version(self, pkg_name, pkg_version=None):
		key = (pkg_name, pkg_version, 'target_version')
		if key not in self._query_cache:
			metadata = self.get_metadata(pkg_name=pkg_name, pkg_version=pkg_version)
			if not metadata or 'info' not in metadata or 'classifiers' not in metadata['info']:
				logging.error("pkg %s don't have classifiers! defaulting to python2!", pkg_name)
				self._query_cache[key] = 'python2'
			else:
				if any(cf.startswith('Programming Language :: Python :: 2') for cf in metadata['info']['classifiers']):
					self._query_cache[key] = 'python2'
				elif any(cf.startswith('Programming Language :: Python :: 3') for cf in metadata['info']['classifiers']):
					self._query_cache[key] = 'python3'
				else:
					logging.error("pkg %s has unknown classifiers %s!", pkg_name, metadata['info']['classifiers'])
					self._query_cache[key] = 'python2'
		return self._query_cache[key]

	def _get_pkg_fname(self, pkg_name, pkg_version=None, suffix='tar.gz'):
		if pkg_version is None:
			return '%s-*.%s' % (pkg_name, suffix)
		else:
			return '%s-%s.%s' % (pkg_name, pkg_version, suffix)

	def download(self, pkg_name, pkg_version=None, outdir=None, binary=False, with_dep=False):
		pip_cmd = 'pip2' if self._get_py_version(pkg_name=pkg_name, pkg_version=pkg_version) == 'python2' else 'pip3'
		if pkg_version:
			download_cmd = [pip_cmd, 'download', '%s==%s' % (pkg_name, pkg_version)]
		else:
			download_cmd = [pip_cmd, 'download', pkg_name]
		if not binary:
			download_cmd += ['--no-binary', ':all:']
		if not with_dep:
			download_cmd += ['--no-deps']
		exec_command('pip download', download_cmd, cwd=outdir)
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

	def install(self, pkg_name, pkg_version=None, trace=False, trace_string_size=1024, install_dir=None, outdir=None,
				sudo=False):
		pip_cmd = 'pip2' if self._get_py_version(pkg_name=pkg_name, pkg_version=pkg_version) == 'python2' else 'pip3'
		if pkg_version:
			install_cmd = [pip_cmd, 'install', '%s==%s' % (pkg_name, pkg_version)]
		else:
			install_cmd = [pip_cmd, 'install', pkg_name]
		if install_dir:
			# NOTE: --prefix and --user are conflicting options, and cannot be both specified
			install_cmd += ['--prefix', install_dir]
			if sudo:
				install_cmd = ['sudo'] + install_cmd
		else:
			if sudo:
				install_cmd = ['sudo'] + install_cmd
			else:
				install_cmd += ['--user']
		install_cmd = self.decorate_strace(pkg_name=pkg_name, pkg_version=pkg_version, trace=trace,
										   trace_string_size=trace_string_size, sudo=sudo, outdir=outdir,
										   command=install_cmd)
		exec_command('pip install', install_cmd)

	def install_file(self, infile, trace=False, trace_string_size=1024, sudo=False, install_dir=None, outdir=None):
		# FIXME: pip2 and pip3 is not available here!
		# FIXME: install prebuilt wheel file is better and doesn't require extra dependencies.
		# FIXME: install tarball file in python is not encouraged, because the building process may fail.
		pip_cmd = 'pip2'
		install_cmd = [pip_cmd, 'install', infile]
		if sudo:
			install_cmd = ['sudo'] + install_cmd
		else:
			install_cmd += ['--user']
		install_cmd = self.decorate_strace_file(infile=infile, trace=trace, trace_string_size=trace_string_size,
												sudo=sudo, outdir=outdir, command=install_cmd)
		exec_command('pip install file', install_cmd)

	def uninstall(self, pkg_name, pkg_version=None, trace=False, trace_string_size=1024, sudo=False, install_dir=None,
				  outdir=None):
		pip_cmd = 'pip2' if self._get_py_version(pkg_name=pkg_name, pkg_version=pkg_version) == 'python2' else 'pip3'
		if pkg_version:
			uninstall_cmd = [pip_cmd, 'uninstall', '%s==%s' % (pkg_name, pkg_version)]
		else:
			uninstall_cmd = [pip_cmd, 'uninstall', pkg_name]
		if sudo:
			uninstall_cmd = ['sudo'] + uninstall_cmd
		else:
			uninstall_cmd += ['--user']
		uninstall_cmd = self.decorate_strace(pkg_name=pkg_name, pkg_version=pkg_version, trace=trace,
											 trace_string_size=trace_string_size, sudo=sudo, outdir=outdir,
											 command=uninstall_cmd)
		exec_command('pip uninstall', uninstall_cmd)

	def download_package(self, pkg_metadata, ver_str=None):
		pass

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
			logging.error("fail in get_metadata for pkg %s, ignoring!\n%s", pkg_name, str(e))
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

	def get_versions(self, pkg_name, max_num=15, min_gap_days=30, with_time=False, pkg_info=None):
		if not pkg_info:
			pkg_info = self.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
		assert pkg_info and 'info' in pkg_info, "Failed to fetch metadata!"
		# skip versions that don't have a distribution
		version_dists = [(ver, dists) for ver, dists in pkg_info['releases'].items() if len(dists) > 0]
		# pick the latest dist upload time for each version
		version_date = [(ver, sorted([dateutil.parser.parse(dist['upload_time']) for dist in dists], reverse=True)[0])
						for ver, dists in version_dists]
		return self.filter_versions(version_date=version_date, max_num=max_num, min_gap_days=min_gap_days,
									with_time=with_time)

	def get_description(self, pkg_name, ver_str=None, pkg_info=None):
		try:
			if not pkg_info:
				pkg_info = self.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
			assert pkg_info and 'info' in pkg_info, "Failed to fetch metadata!"
			return pkg_info['info']['description']
		except Exception as e:
			logging.error(str(e))
			return None

	def get_repo(self, pkg_name, ver_str=None, pkg_info=None):
		try:
			if not pkg_info:
				pkg_info = self.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
			assert pkg_info and 'info' in pkg_info, "Failed to fetch metadata!"
			try:
				return pkg_info['info']['project_urls']['Source']
			except KeyError:
				return None
		except Exception as e:
			logging.error(str(e))
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

	def get_author(self, pkg_name, ver_str=None, pkg_info=None):
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

	def _get_pip_show_pkgs(self, pkg_name, pkg_version=None, install_env=None):
		# run pip show to get the dependent packages
		pip_cmd = 'pip2' if self._get_py_version(pkg_name=pkg_name, pkg_version=pkg_version) == 'python2' else 'pip3'
		show_cmd = [pip_cmd, 'show', pkg_name]
		pkg_info_str = exec_command('pip show', show_cmd, ret_stdout=True, env=install_env)
		pkg_info_msg = HeaderParser().parsestr(pkg_info_str)
		pkg_info = {k: v for k, v in pkg_info_msg.items()}
		if "Requires" in pkg_info and pkg_info["Requires"]:
			dep_pkg_names = [dep_pkgname.strip() for dep_pkgname in pkg_info["Requires"].split(',')]
		else:
			dep_pkg_names = []
		return [dpn.lower() for dpn in dep_pkg_names]

	def _get_pip_dep_pkgs(self, pkg_name, pkg_version=None, install_env=None):
		# Use metadata or pip show to get pip dependencies.
		pkg_info = self.get_metadata(pkg_name=pkg_name, pkg_version=pkg_version)
		if pkg_info and 'info' in pkg_info and 'requires_dist' in pkg_info['info']:
			pkg_info_deps = pkg_info['info']['requires_dist']
			if pkg_info_deps:
				# "lxml; extra == 'lxml'"
				# "PyPyDispatcher (>=2.1.0); platform_python_implementation == \"PyPy\""
				# "w3lib (>=1.17.0)"
				pkg_info_deps = [pid.lower() for pid in pkg_info_deps]
				return [pkg_resources.Requirement.parse(dep_info).project_name for dep_info in pkg_info_deps]
			else:
				logging.info("pkg %s requires_dist is not available, falling back to pip show", pkg_name)
				return self._get_pip_show_pkgs(pkg_name=pkg_name, pkg_version=pkg_version, install_env=install_env)
		return []

	def _get_pip_freeze_pkgs(self, pkg_name, pkg_version=None, install_env=None):
		# NOTE: pkg_version is a placeholder for callbacks and is not used here.
		dep_pkg_names = self._get_pip_dep_pkgs(pkg_name=pkg_name, pkg_version=pkg_version, install_env=install_env)
		# run pip freeze to get the dependencies
		pip_cmd = 'pip2' if self._get_py_version(pkg_name=pkg_name, pkg_version=pkg_version) == 'python2' else 'pip3'
		freeze_cmd = [pip_cmd, 'freeze']
		installed_pkgs_str = exec_command('pip freeze', freeze_cmd, ret_stdout=True, env=install_env)
		installed_pkgs = [dep_pkg.split('==') for dep_pkg in filter(bool, installed_pkgs_str.split('\n'))
						  if len(dep_pkg.split('==')) == 2]
		dep_pkgs = {dep_name: dep_version for dep_name, dep_version in installed_pkgs if dep_name.lower() in dep_pkg_names}
		return dep_pkgs

	def get_dep(self, pkg_name, pkg_version=None, flatten=False, cache_only=False):
		# FIXME: Alternatively, use virtualenv to install package and its dependencies locally, similar to npmjs.
		super(PypiProxy, self).get_dep(pkg_name=pkg_name, pkg_version=pkg_version, flatten=flatten,
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
				elif self.dep_format == 'requirement':
					return dict(dep_pkg.split('==')[:2] for dep_pkg in filter(bool, open(dep_file, 'r').read().split('\n')))
				else:
					logging.error("get_dep: output format %s is not supported!", self.dep_format)
					return None
		if cache_only:
			return None
		# run pip install
		temp_install_dir = tempfile.mkdtemp(prefix='get_dep-')
		self.install(pkg_name=pkg_name, pkg_version=pkg_version, install_dir=temp_install_dir)
		# run pip show and pip freeze to get the dependencies
		# https://stackoverflow.com/questions/2231227/python-subprocess-popen-with-a-modified-environment
		temp_env = os.environ.copy()
		python_version = self._get_py_version(pkg_name=pkg_name, pkg_version=pkg_version)
		temp_env["PYTHONPATH"] = "{0}/lib/{1}/site-packages/".format(
			temp_install_dir, 'python2.7' if python_version == 'python2' else 'python3.5')
		dep_pkgs = self._get_pip_freeze_pkgs(pkg_name=pkg_name, pkg_version=pkg_version, install_env=temp_env)
		# recursively get the flatten dependency packages, useful for static analysis
		flatten_dep_pkgs = self.bfs_all_deps(dep_func_name='_get_pip_freeze_pkgs', pkg_name=pkg_name,
											 pkg_version=pkg_version, temp_env=temp_env) if len(dep_pkgs) > 0 else {}
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
			elif self.dep_format == 'requirement':
				open(dep_file, 'w').write("\n".join(['%s==%s' % (dep_name, dep_version)
													 for dep_name, dep_version in dep_pkgs.items()]))
				open(flatten_dep_file, 'w').write("\n".join(['%s==%s' % (dep_name, dep_version)
															 for dep_name, dep_version in flatten_dep_pkgs.items()]))
			else:
				logging.error("get_dep: output format %s is not supported!", self.dep_format)
		# remove the installation directory
		shutil.rmtree(temp_install_dir)
		return flatten_dep_pkgs if flatten else dep_pkgs

	def install_dep(self, pkg_name, pkg_version=None, trace=False, trace_string_size=1024, sudo=False, install_dir=None,
					outdir=None):
		# install the package, get its dependency, and then install the dependencies
		dep_file = self.get_dep_file(pkg_name=pkg_name, pkg_version=pkg_version)
		pip_cmd = 'pip2' if self._get_py_version(pkg_name=pkg_name, pkg_version=pkg_version) == 'python2' else 'pip3'
		install_dep_cmd = [pip_cmd, 'install', '-r', dep_file]
		if sudo:
			install_dep_cmd = ['sudo'] + install_dep_cmd
		else:
			install_dep_cmd += ['--user']
		install_dep_cmd = self.decorate_strace(pkg_name=pkg_name, pkg_version=pkg_version, trace=trace,
											   trace_string_size=trace_string_size, sudo=sudo, outdir=outdir,
											   command=install_dep_cmd, is_dep=True)
		exec_command('pip install dependency', install_dep_cmd)

	def has_install(self, pkg_name, pkg_version=None, binary=False, with_dep=False):
		# python packages always have a setup.py
		return True

	def test(self, pkg_name, pkg_version=None, trace=False, trace_string_size=1024, sudo=False, install_dir=None,
			 outdir=None, timeout=None):
		pass

	def has_test(self, pkg_name, pkg_version=None, binary=False, with_dep=False):
		# FIXME: based on my research so far, there is test_suite in setuptools, but pkg_resources cannot access them.
		# setup instructions
		# https://setuptools.readthedocs.io/en/latest/setuptools.html
		# test_suite in setup.py
		# https://stackoverflow.com/questions/17001010/how-to-run-unittest-discover-from-python-setup-py-test
		return False

	def main(self, pkg_name, pkg_version=None, trace=False, trace_string_size=1024, sudo=False, install_dir=None,
			 outdir=None, timeout=None):
		# run the python scripts created for package main.
		if self._get_py_version(pkg_name=pkg_name, pkg_version=pkg_version) == 'python2':
			main_cmd = ['python', 'main.py', pkg_name]
			exec_command('python main.py', main_cmd, cwd='pm_proxy/scripts', timeout=timeout)
		else:
			main_cmd = ['python3', 'main.py', pkg_name]
			exec_command('python3 main.py', main_cmd, cwd='pm_proxy/scripts', timeout=timeout)

	def has_main(self, pkg_name, pkg_version=None, binary=False, with_dep=False):
		# if using setuptools, entry_points in setup.py
		# console_scripts and gui_scripts
		# https://packaging.python.org/specifications/entry-points/
		return True

	def exercise(self, pkg_name, pkg_version=None, trace=False, trace_string_size=1024, sudo=False, install_dir=None,
				 outdir=None, timeout=None):
		# run the python script created for package exercise.
		if self._get_py_version(pkg_name=pkg_name, pkg_version=pkg_version) == 'python2':
			exercise_cmd = ['python', 'exercise.py', pkg_name]
			exec_command('python exercise.py', exercise_cmd, cwd='pm_proxy/scripts', timeout=timeout)
		else:
			exercise_cmd = ['python3', 'exercise_py3.py', pkg_name]
			exec_command('python exercise_py3.py', exercise_cmd, cwd='pm_proxy/scripts', timeout=timeout)

	def has_exercise(self, pkg_name, pkg_version=None, binary=False, with_dep=False):
		# if using setuptools, py_modules in setup.py
		# if using setuptools, packages in setup.py, can be generated using setuptools.find_packages
		return True
