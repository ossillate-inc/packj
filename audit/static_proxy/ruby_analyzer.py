import os
import inspect
import logging
from os.path import join

from util.job_util import read_proto_from_file, write_proto_to_file, exec_command
from util.enum_util import LanguageEnum

from .static_base import StaticAnalyzer

from audit.proto.python.ast_pb2 import PkgAstResults, AstLookupConfig
from audit.proto.python.module_pb2 import ModuleStatic
from util.job_util import write_dict_to_file

logging.getLogger().setLevel(logging.ERROR)

class RubyAnalyzer(StaticAnalyzer):
	def __init__(self):
		super(RubyAnalyzer, self).__init__()
		self.language = LanguageEnum.ruby

	def astgen(self, inpath, outfile, root=None, configpath=None, pkg_name=None, pkg_version=None, evaluate_smt=False):
		analyze_path, is_decompress_path, outfile, root, configpath = self._sanitize_astgen_args(
			inpath=inpath, outfile=outfile, root=root, configpath=configpath, language=self.language)

		configpb = AstLookupConfig()
		configpath_bin = configpath + '.bin'

		# parse composition
		composition = {
			"Files" : [],
			"Functions" : [],
			"Calls" : [],
		}
		allfiles, infiles, root = self._get_infiles(inpath=analyze_path, root=root, language=self.language)

		for infile in allfiles:
			try:
				all_source = open(infile, 'r').read()
			except Exception as e:
				logging.warning("Failed to read file %s: %s" % (infile, str(e)))
				continue

			try:
				file_details = {
					"Name"	: infile,
					"LoC"	: len(all_source.split('\n')),
					"Native" : infile in infiles,
				}
				composition["Files"].append(file_details)
			except Exception as e:
				logging.debug("Failed to parse FILE %s ast details: %s!" % (infile, str(e)))

			if infile not in infiles:
				continue

		cwd = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
		astgen_bin = os.path.join(cwd, 'astgen.rb')
		assert os.path.exists(astgen_bin), f'{astgen_bin} does not exist'

		# create binary config from text format
		self._pb_text_to_bin(proto=configpb, infile=configpath, outfile=configpath_bin)
		astgen_cmd = ['ruby', '-W0', astgen_bin, '-c', configpath_bin, '-i', analyze_path, '-o', outfile]

		if root is not None:
			astgen_cmd.extend(['-b', root])
		if pkg_name is not None:
			astgen_cmd.extend(['-n', pkg_name])
		if pkg_version is not None:
			astgen_cmd.extend(['-v', pkg_version])
		try:
			stdout, stderr, error = exec_command('ruby astgen', astgen_cmd, redirect_mask=3)
			assert not error, "could not generate AST"
		except Exception as e:
			logging.debug("Failed to exec %s: %s!" % (astgen_cmd, str(e)))
			return None

		# convert binary output to text format
		resultpb = PkgAstResults()
		read_proto_from_file(resultpb, filename=outfile, binary=True)

		# save AST details
		try:
			logging.warning('writing to %s' % (outfile+'.json'))
			write_dict_to_file(composition, outfile + '.json')
		except Exception as e:
			logging.debug("failed to write ast_details: %s" % (str(e)))

		# save resultpb
		write_proto_to_file(resultpb, filename=outfile, binary=False)

		# clean up residues
		self._cleanup_astgen(analyze_path=analyze_path, is_decompress_path=is_decompress_path)
