import sys
import os

from .static_base import StaticAnalyzer
from packj.audit.static_proxy.analyzer_php_util.detection import *
from packj.util.enum_util import LanguageEnum

class PhpAnalyzer(StaticAnalyzer):
    def __init__(self):
        super(PhpAnalyzer, self).__init__()
        self.language = LanguageEnum.php
    def get_perms(self, inpath, outfile, root=None, configpath=None, pkg_name=None, pkg_version=None, evaluate_smt=False):
        analyze_path, is_decompress_path, outfile, root, configpath = self._sanitize_astgen_args(
			inpath=inpath, outfile=outfile, root=root, configpath=configpath, language=self.language)
        if analyze_path:
            sys.setrecursionlimit(1000000)
            if os.path.isfile(analyze_path):
                analysis(analyze_path)
            else:
                recursive(analyze_path, 0)
            return finalresult()
        return None
        