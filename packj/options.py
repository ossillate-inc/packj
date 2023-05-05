#!/usr/bin/env python

import argparse
from packj import __version__

class Options():
	__args = None

	def args(self):
		return self.__args

	def __init__(self, argv):
		parser = argparse.ArgumentParser(prog=f'packj {__version__}',
						usage='main [options] args',
						description='Packj flags malicious/risky open-source packages')
		subparsers = parser.add_subparsers(title='actions', dest='cmd', help='Command (e.g. auth, audit, sandbox)')

		parser.add_argument('-v', '--version', help='Dump tool version', dest="ver", action='store_true')

		#############################
		# Authenticate sub-command
		#############################
		auth_parser = subparsers.add_parser('auth', help='Authenticate user with the server.')
		auth_parser.add_argument('--force', help='Force user re-authentication', dest="force", action='store_true')

		# Auth optional args
		auth_parser.add_argument("-d", "--debug", dest="debug", \
					help="Enable debugging", action="store_true")

		#############################
		# Audit sub-command
		#############################
		parser_audit = subparsers.add_parser('audit', help='Audit packages for malware/risky attributes')

		# Audit optional args
		parser_audit.add_argument("-d", "--debug", dest="debug", \
					help="Enable debugging", action="store_true")
		parser_audit.add_argument("-t", "--trace", dest="trace", \
				help="Install package(s) and collect dynamic/runtime traces", action="store_true")

		# Audit positional args
		parser_audit_group = parser_audit.add_argument_group(title='required arguments', description='Either --packages or --depfiles must be chosen.')
		parser_audit_arg = parser_audit_group.add_mutually_exclusive_group(required=True)
		parser_audit_arg.add_argument('-p', '--packages', nargs='+', help='Audit packages (e.g., npm:react, pypi:torch), optionally version (e.g., rubygems:overcommit:1.0), local Node/Python packages are also supported (e.g. local_nodejs:/path/to/node-project)', action='store', default=[])
		parser_audit_arg.add_argument('-f', '--depfiles', nargs='+', help='Audit dependencies (e.g., npm:package.json, pypi:requirements.txt)', action='store', default=[])

		#############################
		# Sandbox sub-command
		#############################
		parser_sandbox = subparsers.add_parser('sandbox', help='Sandbox package installation to mitigate risks')

		# Sandbox positional args
		parser_sandbox.add_argument(dest="pm_tool", \
					help="Package manager cmdline tool (e.g., pip, gem, npm)", action="store")
		parser_sandbox.add_argument(dest="install_kw", choices=['install'], \
					help="'install' keyword (expected second arg)", action="store")
		parser_sandbox.add_argument(dest="install_args", nargs=argparse.REMAINDER, \
					help="Install args (e.g., package name, version, other args)", action="store")

		# parse args now
		self.__args = parser.parse_args(argv)

if __name__ == '__main__':
	import sys
	opts = Options(sys.argv[1:])
	print(opts.args())
