import os
import logging
from os.path import basename
from collections import Counter

import esprima
import subprocess

import proto.python.ast_pb2 as ast_pb2
from util.enum_util import LanguageEnum
from util.job_util import read_proto_from_file, write_proto_to_file, exec_command
from static_base import StaticAnalyzer
from proto.python.ast_pb2 import PkgAstResults, AstLookupConfig
from proto.python.module_pb2 import ModuleStatic

logging.getLogger().setLevel(logging.ERROR)

def get_source_text(source, source_range):
    # borrowed from https://bitbucket.org/plas/thonny/src/master/thonny/ast_utils.py
    lines = source.splitlines(True)
    start_row = source_range.start.line
    start_col = source_range.start.column
    end_row = source_range.end.line
    end_col = source_range.end.column
    # get relevant lines
    lines = lines[start_row - 1:end_row]

    # trim last and first lines
    lines[-1] = lines[-1][:end_col]
    lines[0] = lines[0][start_col:]
    return "".join(lines)


class JavaScriptDeclRefVisitor(esprima.NodeVisitor):
    def __init__(self, source, configpb=None, debug=False):
        self.source = source
        self.debug = debug
        self.save_feature = configpb.save_feature if configpb else False
        self.func_only = configpb.func_only if configpb else False

        # initialize the declaration filters
        self.declrefs_filter_set = None
        if configpb is not None:
            self.declrefs_filter_set = set()
            for api in configpb.apis:
                if api.type == ast_pb2.AstNode.FUNCTION_DECL_REF_EXPR:
                    if self.func_only:
                        name_to_check = '.' + api.name if api.base_type else api.name
                        self.declrefs_filter_set.add(name_to_check)
                    else:
                        self.declrefs_filter_set.add(api.full_name)
        # the collected declaration references
        self.declrefs = []

    def visit_MethodDefinition(self, node):
        pass

    def visit_ClassDeclaration(self, node):
        pass

    def visit_NewExpression(self, node):
        logging.warning('visiting New node: %s', node)

        # compute base and func
        if node.callee.type == "Identifier":
            base = None
            name = node.callee.name
        else:
            base = "dummy"
            name = get_source_text(self.source, node.callee.loc)
            logging.warning("callee %s with node.callee.type %s is unhandled!",
                          name, node.callee.type)

        # compute arguments
        args = []
        for arg_index, arg_node in enumerate(node.arguments):
            args.append(get_source_text(self.source, arg_node.loc))

        # log stuff
        if base:
            logging.warning("calling function %s.%s with args %s at line %d", base, name, args, node.loc.start.line)
        else:
            logging.warning("calling function %s with args %s at line %d", name, args, node.loc.start.line)

        full_name = name if base is None else '%s.%s' % (base, name)
        source_text = get_source_text(self.source, node.loc)
        source_range = ((node.loc.start.line, node.loc.start.column),
                        (node.loc.end.line, node.loc.end.column))
        if self.func_only:
            name_to_check = '.' + name if base else name
        else:
            name_to_check = full_name
        if self.declrefs_filter_set is None or name_to_check in self.declrefs_filter_set:
            self.declrefs.append((base, name, tuple(args), source_text, source_range))
        esprima.NodeVisitor.generic_visit(self, node)

    def visit_CallExpression(self, node):
        logging.warning('visiting Call node: %s', node)

        # compute base and func
        if node.callee.type == "Identifier":
            base = None
            name = node.callee.name
        elif node.callee.type == "MemberExpression":
            if node.callee.property.type == "Identifier":
                name = node.callee.property.name
            else:
                name = get_source_text(self.source, node.callee.property.loc)
                logging.warning("node.callee.property.type is %s!", node.callee.property.type)
            if node.callee.object.type == "Identifier":
                base = node.callee.object.name
            else:
                base = get_source_text(self.source, node.callee.object.loc)
                logging.warning("node.callee.object.type is %s!", node.callee.object.type)
        else:
            base = 'dummy'
            name = get_source_text(self.source, node.callee.loc)
            logging.warning("callee %s with node.callee.type %s is unhandled!",
                          name, node.callee.type)

        # compute arguments
        args = []
        for arg_index, arg_node in enumerate(node.arguments):
            args.append(get_source_text(self.source, arg_node.loc))

        # log stuff
        if base:
            logging.warning("calling function %s.%s with args %s at line %d", base, name, args, node.loc.start.line)
        else:
            logging.warning("calling function %s with args %s at line %d", name, args, node.loc.start.line)

        full_name = name if base is None else '%s.%s' % (base, name)
        source_text = get_source_text(self.source, node.loc)
        source_range = ((node.loc.start.line, node.loc.start.column),
                        (node.loc.end.line, node.loc.end.column))
        if self.func_only:
            name_to_check = '.' + name if base else name
        else:
            name_to_check = full_name
        if self.declrefs_filter_set is None or name_to_check in self.declrefs_filter_set:
            self.declrefs.append((base, name, tuple(args), source_text, source_range))
        esprima.NodeVisitor.generic_visit(self, node)

    def get_declrefs(self):
        return self.declrefs



class JsAnalyzer(StaticAnalyzer):
    def __init__(self):
        super(JsAnalyzer, self).__init__()
        self.language = LanguageEnum.javascript

    def astgen(self, inpath, outfile, root=None, configpath=None, pkg_name=None, pkg_version=None, evaluate_smt=False):
        """
        There are two ways to implement the javascript ast parsing, each of them has their cons and pros.
        One is to directly use the npm esprima module, the other is to use the pypi esprima module.

        1. The npm module is the latest version and has lots of features to use directly. But it doesn't have a visitor
        and requires manually implementation.
        2. The pypi module is claimed to be a line by line translation of esprima in python, but it may be outdated and
        inactively maintained. However, it contains a visitor similar to python ast.NodeVisitor that we can directly use.

        To minimize the efforts, I currently choose the latter.
        """
        analyze_path, is_decompress_path, outfile, root, configpath = self._sanitize_astgen_args(
            inpath=inpath, outfile=outfile, root=root, configpath=configpath, language=self.language)

        # load the config proto
        configpb = AstLookupConfig()
        read_proto_from_file(configpb, configpath, binary=False)
        logging.debug("loaded lookup config from %s:\n%s", configpath, configpb)
        # invoke the language specific ast generators to call functions

        # FIXME: current testdata sometimes fails the analyzer, inspect it!
        # get input files
        infiles, root = self._get_infiles(inpath=analyze_path, root=root, language=self.language)

        # initialize resultpb
        resultpb = PkgAstResults()
        pkg = resultpb.pkgs.add()
        pkg.config.CopyFrom(configpb)
        pkg.pkg_name = pkg_name if pkg_name is not None else basename(analyze_path)
        if pkg_version is not None:
            pkg.pkg_version = pkg_version
        pkg.language = ast_pb2.JAVASCRIPT
        for infile in infiles:
            all_source = open(infile, 'r').read()
            try:
                # tree = esprima.parseModule(), esprima.parseScript()
                tree = esprima.parse(all_source, options={'loc': True})
            except Exception as e:
                logging.warning("Fatal error %s parsing file %s! Skipping this file!", e, infile)
                continue
            visitor = JavaScriptDeclRefVisitor(source=all_source, configpb=configpb)
            visitor.visit(tree)
            logging.warning("collected functions: %s", Counter(visitor.get_declrefs()).items())

            filepb = self._get_filepb(infile, root)
            for base, name, args, source_text, source_range in visitor.get_declrefs():
                api_result = self._get_api_result(base, name, args, source_text, source_range, filepb)
                pkg.api_results.add().CopyFrom(api_result)

        # optionally evaluate smt formula
        if evaluate_smt:
            satisfied = self._check_smt(astgen_results=[resultpb], configpath=configpath)
            resultpb.pkgs[0].config.smt_satisfied = satisfied

        # save resultpb
        write_proto_to_file(resultpb, outfile, binary=False)

        # clean up residues
        self._cleanup_astgen(analyze_path=analyze_path, is_decompress_path=is_decompress_path)
