#!/usr/bin/env python

from __future__ import print_function

import sys
import os

# sys.version_info[0] is the major version number. sys.version_info[1] is minor
if sys.version_info[0] != 3:
	print('\n*** WARNING *** Please use Python 3! Exiting.')
	exit(1)

def main(config:str='.packj.yaml'):
	try:
		# parse command line args
		from packj.options import Options
		opts = Options(sys.argv[1:])
		assert opts, 'Failed to parse cmdline args!'

		args = opts.args()
		assert args, 'Failed to get cmdline args!'

		# version request
		if args.ver and not args.cmd:
			from packj import __version__
			print(__version__)
			exit(1)

		# configuration file
		if not os.path.exists(config):
			config = os.path.expanduser(os.path.join('~', f'{config}'))
		assert os.path.exists(config), f'No {config} file found'

		# auth request
		if args.cmd == 'auth':
			from packj.auth.main import main
			main(args, config)

		# audit request
		elif args.cmd == 'audit':
			from packj.audit.main import main
			main(args, config)

		# sandbox install
		elif args.cmd == 'sandbox':
			from packj.sandbox.main import main
			main(args, config)

	except Exception as e:
		print(str(e))
		exit(1)
