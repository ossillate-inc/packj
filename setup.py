from setuptools import setup, find_packages

from setuptools.command.build_ext import build_ext
from setuptools.command.install import install

from distutils.errors import DistutilsSetupError
from distutils import log as distutils_logger

import setuptools

import os, subprocess

here = os.path.abspath(os.path.dirname(__file__))

# package descr
long_description = open(os.path.join(here, "README.md")).read()
long_description_content_type = 'text/markdown'

sandbox_ext = setuptools.extension.Extension('sandbox',
					 sources = ['sandbox/sandbox.o'])

# this grabs the requirements from requirements.txt
REQUIREMENTS = [i.strip().split('==')[0] for i in open(os.path.join(here, "requirements.txt")).readlines()]

sandbox_ext = setuptools.extension.Extension('packj.sandbox_ext', sources = ['sandbox/sandbox.o'])

def setup_sandbox(build_dir):
	try:
		import sys
		if sys.platform != 'linux':
			return

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
	except Exception as e:
		distutils_logger.error(f'FAILED: {str(e)}')

class specialized_build_ext(build_ext, object):
	special_extension = sandbox_ext.name

	def build_extension(self, ext):
		if ext.name!=self.special_extension:
			# Handle unspecial extensions with the parent class' method
			super(specialized_build_ext, self).build_extension(ext)
		else:
			# Handle special extension
			build_dir = os.path.realpath(self.build_lib)
			root_dir = os.path.dirname(os.path.realpath(__file__))
			target_dir = build_dir if not self.inplace else root_dir

			setup_sandbox(target_dir)

			# After making the library build the c library's python interface with the parent build_extension method
			#super(specialized_build_ext, self).build_extension(ext)

setup(
	name = 'packj',
	packages=find_packages(),
	package_data = {
		'packj.sandbox' : ['*.o', 'Makefile'],
		'packj.audit.config' : ['*.*', 'python_api/*.*', 'javascript_api/*.*', 'rubygems_api/*.*'],
		'packj.audit.pm_proxy' : ['*.rb'],
		'packj.audit.strace_parser' : ['rules.yaml'],
		'packj.audit.static_proxy' : ['*.rb'],
		'packj.audit.proto' : ['ruby/*.rb'],
	},
	version = '0.1',
	license='MIT',
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
			'packj=packj.main:main',
		],
	},
	ext_modules = [sandbox_ext],
	cmdclass = {'build_ext': specialized_build_ext},
	classifiers=[
		'Development Status :: 3 - Alpha',
		'Intended Audience :: Developers',
		'Topic :: Software Development :: Build Tools',
		'License :: OSI Approved :: MIT License',
		'Programming Language :: Python :: 3',
		'Programming Language :: Python :: 3.4',
		'Programming Language :: Python :: 3.5',
		'Programming Language :: Python :: 3.6',
	],
)
