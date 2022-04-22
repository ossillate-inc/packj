import os
import logging
import shutil
import tempfile
import re

from os.path import join, exists, abspath, isdir, isfile, dirname, basename, relpath

import proto.python.ast_pb2 as ast_pb2
from pm_util import get_pm_proxy_for_language, get_pm_proxy
from util.enum_util import LanguageEnum
from util.compress_files import decompress_file, get_file_with_meta
from util.job_util import read_proto_from_file, write_proto_to_file, exec_command
from proto.python.ast_pb2 import PkgAstResults, AstLookupConfig, FileInfo, AstNode
from proto.python.module_pb2 import ModuleStatic


Language2Extensions = {
    LanguageEnum.python: ('.py',),
    LanguageEnum.javascript: ('.js',),
    LanguageEnum.ruby: ('.rb',),
    LanguageEnum.java: ('.java', '.class', '.jar', '.aar', '.war', '.dex', '.apk'),  # java packages are compiled
    LanguageEnum.csharp: ('.cs',),  # c# packages are compiled and are windows binaries/libraries
    LanguageEnum.php: ('.php',)
}


class StaticAnalyzer(object):
    def __init__(self):
        self.language = None

    def astgen(self, inpath, outfile, root=None, configpath=None, pkg_name=None, pkg_version=None, evaluate_smt=False):
        """
        Detects usage of sensitive APIs.
        """
        pass

    def taint(self, inpath, outfile, configpath=None, pkg_name=None, pkg_version=None):
        """
        Identify data flow from sources to sinks.

        This helps identify stealer, backdoor, and user-controlled sabotage. The returned message is of class module_pb2.ModuleStatic.
        """
        pass

    def get_taint_result(self, pm_proxy, pkg_name, outdir, configpath=None, pkg_version=None, cache_only=False):
        taint_fname = pm_proxy.get_taint_fname(pkg_name=pkg_name, pkg_version=pkg_version)
        taint_file = join(outdir, taint_fname)
        taint_result = None
        if exists(taint_file):
            logging.warning("get_taint_result: using cached taint_file %s!", taint_file)
            taint_result = ModuleStatic()
            read_proto_from_file(taint_result, taint_file, binary=False)
        else:
            if cache_only:
                logging.warning("skipping unprocessed pkg %s ver %s due to cache_only!", pkg_name, pkg_version)
                return taint_result
            # download current package and analyze it
            tempdir = tempfile.mkdtemp(prefix='taint-')
            pm_proxy.download(pkg_name=pkg_name, pkg_version=pkg_version, outdir=tempdir)
            tempdir_files = os.listdir(tempdir)
            if len(tempdir_files) == 0:
                logging.error("fail to download pkg %s ver %s", pkg_name, pkg_version)
            else:
                pkg_file = join(tempdir, tempdir_files[0])
                self.taint(inpath=pkg_file, outfile=taint_file, configpath=configpath, pkg_name=pkg_name,
                           pkg_version=pkg_version)
                if exists(taint_file):
                    taint_result = ModuleStatic()
                    read_proto_from_file(taint_result, taint_file, binary=False)
                else:
                    logging.error("fail to run taint on downloaded package %s", pkg_file)
            shutil.rmtree(tempdir)
        return taint_result

    def taint_tree(self, pkg_name, outdir, cache_dir=None, configpath=None, pkg_version=None, ignore_dep_version=False,
                   ignore_dep=False):
        """
        Performs static taint analysis on packages and their dependencies, based on sources and sinks.

        This identifies suspicious API calls and flows in packages (i.e. network.read, eval).
        """
        # sanitize language
        if self.language is None:
            raise Exception("Invoking taint on invalid language: %s" % self.language)

        pm_proxy = get_pm_proxy_for_language(language=self.language, cache_dir=cache_dir, isolate_pkg_info=True)
        # check for cached taint
        taint_fname = pm_proxy.get_taint_fname(pkg_name=pkg_name, pkg_version=pkg_version)
        taint_file = join(outdir, taint_fname)
        if exists(taint_file):
            logging.warning("skipping cached taint_file %s!", taint_file)
            return

        # get flattened dependencies, because each package result only contains module summary for itself (no children),
        # but indirect dependencies can be directly imported.
        if not ignore_dep:
            try:
                flatten_dep_pkgs = pm_proxy.get_dep(pkg_name=pkg_name, pkg_version=pkg_version, flatten=True)
            except Exception as gde:
                logging.error("fail to get_dep on pkg %s ver %s: %s", pkg_name, pkg_version, gde)
                return

            # get the taint results for dependent packages
            dep_taint_results = []
            for dep_name, dep_version in flatten_dep_pkgs.items():
                if ignore_dep_version:
                    dep_version = None
                dep_taint_result = self.get_taint_result(pm_proxy=pm_proxy, pkg_name=dep_name, outdir=outdir,
                                                         configpath=configpath, pkg_version=dep_version)
                if dep_taint_result:
                    dep_taint_results.append(dep_taint_result)

            # based on the taint result of the children, generate the new config file and run taint on current package
            tmp_configpath = self._gen_combined_configpath(configpath=configpath, dep_taint_results=dep_taint_results)
            taint_result = self.get_taint_result(pm_proxy=pm_proxy, pkg_name=pkg_name, outdir=outdir,
                                                 configpath=tmp_configpath, pkg_version=pkg_version)
            os.remove(tmp_configpath)
        else:
            taint_result = self.get_taint_result(pm_proxy=pm_proxy, pkg_name=pkg_name, outdir=outdir,
                                                 configpath=configpath, pkg_version=pkg_version)
        if taint_result:
            logging.warning("identified %d flows in %s ver %s", len(taint_result.flows), pkg_name, pkg_version)

    def _gen_combined_configpath(self, configpath, dep_taint_results):
        # load the old config
        configpb = AstLookupConfig()
        read_proto_from_file(configpb, configpath, binary=False)

        # iterate through the taint results to update configpb
        num_new_sources = 0
        num_new_sinks = 0
        for dep_taint_result in dep_taint_results:
            # dep_taint_result is of type module_pb2.ModuleStatic
            for new_source in dep_taint_result.sources:
                configpb.apis.append(new_source.node)
                num_new_sources += 1
            for new_sink in dep_taint_result.sinks:
                configpb.apis.append(new_sink.node)
                num_new_sinks += 1
        if num_new_sources + num_new_sinks > 0:
            logging.warning("added %d new sources and %d new sinks!", num_new_sources, num_new_sinks)

        # generate the new config file
        outf = tempfile.NamedTemporaryFile(prefix='configpath-', delete=False)
        write_proto_to_file(proto=configpb, filename=outf.name, binary=False)
        return outf.name

    def danger(self, pkg_name, outdir, cache_dir=None, configpath=None, pkg_version=None):
        """
        Identify arguments of sensitive APIs
        http://www0.cs.ucl.ac.uk/staff/M.Harman/exe1.html

        This helps identify hard-coded sabotage and argument-specific dangerous calls.
        """
        pass

    def danger_tree(self, pkg_name, outdir, cache_dir=None, configpath=None, pkg_version=None, ignore_dep_version=False,
                    ignore_dep=False):
        """
        Perform static API analysis on packages and their dependencies.

        This identifies suspicious API calls (e.g. rmdir).
        """
        pass

    @staticmethod
    def _sanitize_astgen_args(inpath, outfile, root, configpath, language):
        # get the absolute path
        inpath = abspath(inpath)
        outfile = abspath(outfile)
        if root is not None:
            root = abspath(root)
        if configpath is not None:
            configpath = abspath(configpath)

        # handle the input path
        analyze_path = None
        is_decompress_path = False
        if not exists(inpath):
            raise Exception("inpath %s doesn't exist!" % inpath)
        if isdir(inpath):
            logging.debug("inpath %s is a directory!", inpath)
            analyze_path = inpath
        else:
            logging.debug("inpath %s is a file, checking whether it is a compressed file!", inpath)
            if inpath.endswith(Language2Extensions[language]):
                logging.debug("inpath %s is a single file, directly analyze it!", inpath)
                analyze_path = inpath
            elif inpath.endswith(".gem"):
                # Handle gem file using `gem unpack`
                logging.debug("inpath %s is a gem file, decompress using gem unpack and analyze it!", inpath)
                import tempfile
                analyze_path = tempfile.mkdtemp(prefix='gem-')
                gem_unpack_cmd = ['gem', 'unpack', inpath, '--target', analyze_path]
                exec_command("gem unpack", gem_unpack_cmd)
                is_decompress_path = True
            elif get_file_with_meta(inpath) is not None:
                logging.debug("inpath %s is a compressed file, decompress and analyze it!", inpath)
                analyze_path = decompress_file(inpath)
                is_decompress_path = True
            else:
                raise Exception("inpath %s is unhandled type for language %s!" % (inpath, language))

        return analyze_path, is_decompress_path, outfile, root, configpath

    @staticmethod
    def _cleanup_astgen(analyze_path, is_decompress_path):
        if is_decompress_path:
            shutil.rmtree(analyze_path)

    @staticmethod
    def _pb_text_to_bin(proto, infile, outfile):
        read_proto_from_file(proto=proto, filename=infile, binary=False)
        write_proto_to_file(proto=proto, filename=outfile, binary=True)

    @staticmethod
    def _get_infiles(inpath, root, language):
        infiles = []
        if isfile(inpath):
            if root is None:
                root = dirname(inpath)
            root = abspath(root)
            infiles.append(abspath(inpath))
        elif isdir(inpath):
            if root is None:
                root = inpath
            root = abspath(root)
            for i_root, _, i_files in os.walk(inpath):
                for fname in i_files:
                    if fname.endswith(Language2Extensions[language]):
                        infiles.append(abspath(join(i_root, fname)))
        if len(infiles) == 0:
            logging.error("No input files from %s for language %s", inpath, language)
        return infiles, root

    @staticmethod
    def _get_filepb(infile, root):
        filepb = FileInfo()
        filepb.filename = basename(infile)
        filepb.relpath = relpath(dirname(infile), root)
        filepb.file = relpath(infile, root)
        filepb.directory = root
        return filepb

    @staticmethod
    def _get_api_result(base, name, args, source_text, source_range, filepb):
        api_result = AstNode()
        api_result.type = ast_pb2.AstNode.FUNCTION_DECL_REF_EXPR
        api_result.name = name
        if base is None:
            api_result.full_name = name
        else:
            api_result.base_type = base
            api_result.full_name = '%s.%s' % (base, name)
        for arg in args:
            api_result.arguments.append(arg)
        api_result.source = source_text
        source_start, source_end = source_range
        api_result.range.start.row = source_start[0]
        api_result.range.start.column = source_start[1]
        api_result.range.start.file_info.CopyFrom(filepb)
        api_result.range.end.row = source_end[0]
        api_result.range.end.column = source_end[1]
        api_result.range.end.file_info.CopyFrom(filepb)
        return api_result

    def astfilter(self, pkg_name, outdir, cache_dir=None, configpath=None, pkg_version=None, pkg_manager=None,
                  ignore_dep_version=False, ignore_dep=False):
        """
        Filters packages and their dependencies, based on sensitive APIs and their combinations

        This helps narrow down packages for further analysis.
        """
        # sanitize language
        if self.language is None:
            raise Exception("Invoking astfilter on invalid language: %s" % self.language)

        if pkg_manager is None:
            pm_proxy = get_pm_proxy_for_language(language=self.language, cache_dir=cache_dir, isolate_pkg_info=True)
        else:
            pm_proxy = get_pm_proxy(pm=pkg_manager, cache_dir=cache_dir, isolate_pkg_info=True)
        # check for cached astfilter file
        astfilter_fname = pm_proxy.get_astfilter_fname(pkg_name=pkg_name, pkg_version=pkg_version)
        astfilter_file = join(outdir, astfilter_fname)
        if exists(astfilter_file):
            logging.warning("skipping cached astfilter_file %s!", astfilter_file)
            return

        # get the astgen results for the main package as well as its dependent packages
        astgen_results = []
        main_astgen_result = self.get_astgen_result(pm_proxy=pm_proxy, pkg_name=pkg_name, outdir=outdir,
                                                    configpath=configpath, pkg_version=pkg_version)
        if main_astgen_result:
            astgen_results.append(main_astgen_result)
        else:
            logging.error("fail to run astfilter on pkg %s ver %s", pkg_name, pkg_version)
            return

        # get flattened dependencies and their astgen results
        if not ignore_dep:
            try:
                flatten_dep_pkgs = pm_proxy.get_dep(pkg_name=pkg_name, pkg_version=pkg_version, flatten=True)
            except Exception as gde:
                logging.error("fail to get_dep on pkg %s ver %s: %s", pkg_name, pkg_version, gde)
                return

            for dep_name, dep_version in flatten_dep_pkgs.items():
                if ignore_dep_version:
                    dep_version = None
                dep_astgen_result = self.get_astgen_result(pm_proxy=pm_proxy, pkg_name=dep_name, outdir=outdir,
                                                           configpath=configpath, pkg_version=dep_version)
                if dep_astgen_result:
                    astgen_results.append(dep_astgen_result)

        # check satisfiability of the specified smt formula and dump the corresponding output
        satisfied = StaticAnalyzer._check_smt(astgen_results=astgen_results, configpath=configpath)
        main_astgen_result.pkgs[0].config.smt_satisfied = satisfied

        # TODO: maybe record the suspicious API usage in each dependent package as well
        # dump the astfilter result to file
        write_proto_to_file(proto=main_astgen_result, filename=astfilter_file, binary=False)

    def get_astgen_result(self, pm_proxy, pkg_name, outdir, configpath=None, pkg_version=None, cache_only=False):
        astgen_fname = pm_proxy.get_astgen_fname(pkg_name=pkg_name, pkg_version=pkg_version)
        astgen_file = join(outdir, astgen_fname)
        astgen_result = None
        if exists(astgen_file):
            logging.warning("get_astgen_result: using cached astgen_file %s!", astgen_file)
            astgen_result = PkgAstResults()
            read_proto_from_file(astgen_result, astgen_file, binary=False)
        else:
            if cache_only:
                logging.warning("skipping unprocessed pkg %s ver %s due to cache_only!", pkg_name, pkg_version)
                return astgen_result
            # download current package and analyze it
            tempdir = tempfile.mkdtemp(prefix='astfilter-')
            pm_proxy.download(pkg_name=pkg_name, pkg_version=pkg_version, outdir=tempdir)
            tempdir_files = os.listdir(tempdir)
            if len(tempdir_files) == 0:
                logging.error("fail to download pkg %s ver %s", pkg_name, pkg_version)
            else:
                pkg_file = join(tempdir, tempdir_files[0])
                self.astgen(inpath=pkg_file, outfile=astgen_file, configpath=configpath, pkg_name=pkg_name,
                            pkg_version=pkg_version)
                if exists(astgen_file):
                    astgen_result = PkgAstResults()
                    read_proto_from_file(astgen_result, astgen_file, binary=False)
                else:
                    logging.error("fail to run astgen on downloaded package %s", pkg_file)
            shutil.rmtree(tempdir)
        return astgen_result


    @staticmethod
    def _get_api_partial_name(ast_node):
        if ast_node.full_name == ast_node.name:
            return ast_node.name
        else:
            return "." + ast_node.name

    @staticmethod
    def _get_partial_name2full_names(ast_nodes):
        partial_name2full_name = {}
        for ast_node in ast_nodes:
            partial_name = StaticAnalyzer._get_api_partial_name(ast_node)
            partial_name2full_name.setdefault(partial_name, [])
            partial_name2full_name[partial_name].append(ast_node.full_name)
        return partial_name2full_name

    @staticmethod
    def _check_smt(astgen_results, configpath=None):
        if len(astgen_results) == 0:
            logging.warning("no astgen_results specified, returning False!")
            return False
        # if configpath is not specified, use the config in any of the astgen result, o.w. use configpath
        if configpath:
            configpb = AstLookupConfig()
            read_proto_from_file(configpb, configpath, binary=False)
        else:
            configpb = astgen_results[0].pkgs[0].config
        logging.warning("checking satisfiability of smt formula %s", configpb.smt_formula)

        used_apis = set()

        # FIXME: works if each astgen_result has only one pkg
        # Get the results from the different packages in the astgen results
        for current_package in astgen_results:
            current_package_results = current_package.pkgs[0].api_results
            current_package_config = current_package.pkgs[0].config
            if current_package_results:
                if current_package_config.func_only:
                    # func only match
                    partial_name2full_names = StaticAnalyzer._get_partial_name2full_names(current_package_config.apis)
                    for api_result in current_package_results:
                        partial_name = StaticAnalyzer._get_api_partial_name(api_result)
                        used_apis.update(partial_name2full_names[partial_name])
                else:
                    # full name match
                    for api_result in current_package_results:
                        used_apis.add(api_result.full_name)

        # Transform the names found the astgen results to the numbers used in the formula
        logging.warning("there are %d used apis: %s", len(used_apis), used_apis)
        used_apis_numerical = []

        for current_api in configpb.apis:
            if current_api.full_name in used_apis:
                used_apis_numerical.append(current_api.id)

        # Transform the formula (the variable that will be evaluated is used_apis_numerical)
        smt_formula = re.sub(r'(\d+)', r'(\1 in used_apis_numerical)', configpb.smt_formula)

        satisfied = eval(smt_formula)
        logging.warning("satisfiability = %s", satisfied)
        return satisfied
