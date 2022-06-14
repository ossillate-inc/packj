#!/usr/bin/env python

import argparse

class Options():
	__args = None

	def args(self):
		return self.__args

	def __init__(self, argv):
		parser = argparse.ArgumentParser(prog="packj v0.1",
										 usage="usage: main [options] args",
										 description="Packj flags malicious/risky open-source packages")
		parser.add_argument("-d", "--debug", dest="debug", \
				help="Enable debugging", action="store_true")
		parser.add_argument(dest="pm_name", \
				help="Package manager (e.g., pypi, npm)", action="store")
		parser.add_argument(dest="pkg_name", \
				help="Package name (e.g., react, torch)", action="store")
		self.__args = parser.parse_args(argv)

if __name__ == '__main__':
	import sys
	opts = Options(sys.argv[1:])
	print(opts.args())
