from setuptools import setup, find_packages

from distutils.errors import DistutilsSetupError
from setuptools.command.install import install

from distutils.errors import DistutilsSetupError
from distutils import log as distutils_logger

import setuptools

import shutil
import os, sys, subprocess

here = os.path.abspath(os.path.dirname(__file__))

# package descr
long_description = open(os.path.join(here, "README.md")).read()
long_description_content_type = 'text/markdown'

sandbox_ext = setuptools.extension.Extension('sandbox',
					 sources = ['sandbox/sandbox.o'])

# this grabs the requirements from requirements.txt
REQUIREMENTS = [i.strip().split('==')[0] for i in open(os.path.join(here, "requirements.txt")).readlines()]

def setup_sandbox(build_dir):
	if sys.platform != 'linux':
		raise Exception('Only Linux is supported')

	sbox_dir = os.path.join('packj', 'sandbox')
	sbox_path = os.path.join(here, sbox_dir)
	sbox_build_path = os.path.join(build_dir, sbox_dir)

	make_process = subprocess.Popen(f'./install.sh && make && mv *.so {sbox_build_path} && mv strace {sbox_build_path}',
									 cwd=sbox_path,
									 stderr=subprocess.PIPE,
									 shell=True)
	stderr = make_process.communicate()

	if make_process.returncode:
		raise Exception(f'Failed to install sandbox:\n{stderr}')

def copy_config():
	src_path = os.path.join('packj', 'config.yaml')
	dst_path = os.path.expanduser(os.path.join('~', f'.{src_path}'))
	try:
		shutil.rmtree(os.path.dirname(dst_path))
	except:
		pass
	os.mkdir(os.path.dirname(dst_path))
	shutil.copy(src_path, dst_path)

def remove_config():
	dst_path = os.path.expanduser(os.path.join('~', '.packj'))
	if os.path.exists(dst_path):
		shutil.rmtree(dst_path)

class custom_install(install):
	def run(self):
		try:
			install.run(self)
			target_dir = os.path.realpath(self.build_lib)
			setup_sandbox(target_dir)
			copy_config()
		except Exception as e:
			remove_config()
			distutils_logger.error(f'Installation failed: {str(e)}')
			raise DistutilsSetupError(str(e))

setup(
	name = 'packj',
	packages=find_packages(),
	package_data = {
		'packj.sandbox' : ['*.o', 'Makefile', '*.so', 'strace'],
		'packj.audit.config' : ['*.*', 'python_api/*.*', 'javascript_api/*.*', 'rubygems_api/*.*'],
		'packj.audit.pm_proxy' : ['*.rb'],
		'packj.audit.strace_parser' : ['rules.yaml'],
		'packj.audit.static_proxy' : ['*.rb'],
		'packj.audit.proto' : ['ruby/*.rb'],
	},
	data_files = [
		(os.path.expanduser(os.path.join('~','.packj')), ['packj/config.yaml']),
	],
	version = '0.8',
	license='GNU AGPLv3',
	description = 'Packj flags "risky" open-source packages in your software supply chain',
	long_description=long_description,
	long_description_content_type="text/markdown",
	author = 'Ossillate Inc.',
	author_email = 'oss@ossillate.com',
	url = 'https://github.com/ossillate-inc/packj',
	download_url = 'https://github.com/ossillate-inc/packj/archive/refs/tags/placeholder.tar.gz',
	project_urls={
		"Bug Tracker": "https://github.com/ossillate-inc/packj/issues",
	},
	keywords = ['software supply chain', 'malware', 'typo-squatting', 'vulnerability', 'open-source software', 'software composition analysis'],
	python_requires=">=3.4",
	install_requires=REQUIREMENTS,
	entry_points = {
		'console_scripts': [
			'packj=packj.main:bin_wrapper',
		],
	},
	cmdclass = {
		'install': custom_install,
	},
	classifiers=[
		'Development Status :: 4 - Beta',
		'Intended Audience :: Developers',
		'Topic :: Security',
		'License :: OSI Approved :: GNU Affero General Public License v3',
		'Programming Language :: Python :: 3',
		'Programming Language :: Python :: 3.4',
		'Programming Language :: Python :: 3.5',
		'Programming Language :: Python :: 3.6',
		'Programming Language :: Python :: 3.7',
		'Programming Language :: Ruby',
	],
)
