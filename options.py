#!/usr/bin/env python

import argparse

class Options():
	__args = None

	def args(self):
		return self.__args

	def __init__(self, argv):
		parser = argparse.ArgumentParser(prog='packj v0.1',
						usage='usage: main [options] args',
						description='Packj flags malicious/risky open-source packages')
		subparsers = parser.add_subparsers(title="actions", dest='cmd', help='Command (e.g. audit)')

		# Audit sub-command
		parser_audit = subparsers.add_parser('audit', help='Audit a package for malware/risky attributes')

		# Sandbox sub-command
		parser_sandbox = subparsers.add_parser('sandbox', help='Sandbox package installation to mitigate risks')

		# positional args
		parser_audit.add_argument(dest="pm_name", \
					help="Package manager (e.g., pypi, npm, rubygems)", action="store")
		parser_audit.add_argument(dest="pkg_name", \
					help="Package name (e.g., react, torch, overcommit)", action="store")
		parser_audit.add_argument(dest="ver_str", \
					help="Package version (e.g., 0.0.1), default: latest", nargs='?', const=None, action="store")

		# Audit optional args
		parser_audit.add_argument("-d", "--debug", dest="debug", \
					help="Enable debugging", action="store_true")
		parser_audit.add_argument("-t", "--trace", dest="trace", \
				help="Install package and collect dynamic/runtime trace", action="store_true")

		# Sandbox args
		parser_sandbox.add_argument(dest="pm_tool", \
					help="Package manager CLI tool (e.g., pip, gem, npm)", action="store")
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
