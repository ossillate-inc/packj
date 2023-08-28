import logging
from os.path import exists, join, basename

from packj.util.enum_util import LanguageEnum
from packj.audit.static_proxy.py_analyzer import PyAnalyzer
from packj.audit.static_proxy.js_analyzer import JsAnalyzer
from packj.audit.static_proxy.ruby_analyzer import RubyAnalyzer
from packj.audit.static_proxy.php_analyzer import PhpAnalyzer
from packj.audit.static_proxy.java_analyzer import JavaAnalyzer

def get_static_proxy_for_language(language):
	if language == LanguageEnum.python:
		return PyAnalyzer()
	elif language == LanguageEnum.javascript:
		return JsAnalyzer()
	elif language == LanguageEnum.ruby:
		return RubyAnalyzer()
	elif language == LanguageEnum.php:
		return PhpAnalyzer()
	elif language == LanguageEnum.java:
		return JavaAnalyzer()
	else:
		raise Exception("Static proxy not available for language: %s" % language)

def astgen(inpath, outfile, root=None, configpath=None, language=LanguageEnum.python, pkg_name=None, pkg_version=None,
		   evaluate_smt=False):
	"""
	Parse source file, generate ast and record specified ast nodes.
	"""
	static_proxy = get_static_proxy_for_language(language=language)
	static_proxy.astgen(inpath=inpath, outfile=outfile, root=root, configpath=configpath, pkg_name=pkg_name,
						pkg_version=pkg_version, evaluate_smt=evaluate_smt)
