#
# Based on MalOSS:  https://github.com/osssanitizer/maloss
#
import ast
import logging
from collections import Counter
from os.path import basename

import asttokens

import proto.python.ast_pb2 as ast_pb2
from util.job_util import read_proto_from_file, write_proto_to_file, exec_command
from util.job_util import write_dict_to_file
from util.enum_util import LanguageEnum
from .static_base import StaticAnalyzer
from pyt_run import pyt_run
from proto.python.ast_pb2 import PkgAstResults, AstLookupConfig
from proto.python.module_pb2 import ModuleStatic

logging.getLogger().setLevel(logging.ERROR)

class PythonDeclRefVisitor(ast.NodeVisitor):
    def __init__(self, buf, infile, asttok, configpb=None, debug=False):
        self.asttok = asttok
        self.debug = debug
        self.save_feature = configpb.save_feature if configpb else False
        self.func_only = configpb.func_only if configpb else False
        self.infile = infile
        self.buf = buf

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
        self.name2module = {}
        self.alias2name = {}
        # TODO: Module-based filter may reduce false positives, but can also introduce false negatives if not support cross file/module check.
        # the modules imported in the current file
        self.modules = set()
        # the collected declaration references
        self.declrefs = []

    def generic_visit(self, node):
        ast.NodeVisitor.generic_visit(self, node)
        if self.debug:
            if hasattr(node, 'lineno'):
                logging.warning('visiting %s node at line %d', type(node).__name__, node.lineno)
            else:
                logging.warning('visiting %s node', type(node).__name__)

    def visit_ImportFrom(self, node):
        logging.debug('visiting ImportFrom node (line %d)', node.lineno)
        for name in node.names:
            self.name2module.setdefault(name.name, node.module)
            if name.asname is not None:
                self.alias2name.setdefault(name.asname, name.name)
        ast.NodeVisitor.generic_visit(self, node)

    def visit_FunctionDef(self, node):
        logging.debug('visiting FunctionDef node (line %d)', node.lineno)
        # FIXME: warn about redefined functions?
        if node.name in self.alias2name or node.name in self.name2module:
            logging.warning("redefined imported function %s!", node.name)
        ast.NodeVisitor.generic_visit(self, node)
        if self.save_feature:
            logging.warning("set root_nodes")

    def visit_ClassDef(self, node):
        logging.debug('visiting ClassDef node (line %d)', node.lineno)
        ast.NodeVisitor.generic_visit(self, node)
        if self.save_feature:
            logging.warning("set root_nodes")

    def visit_Call(self, node):
        logging.debug('visiting Call node (line %d)', node.lineno)

        # debug code
        if self.debug:
            for fieldname, value in ast.iter_fields(node):
                logging.warning('fieldname %s, value %s', fieldname, value)
                if fieldname == 'func':
                    for f_fieldname, f_value in ast.iter_fields(value):
                        logging.info('func fieldname %s, func value %s', f_fieldname, f_value)
                        if f_fieldname == 'id':
                            logging.warning('func id: %s', f_value)

        # compute base and func
        if isinstance(node.func, ast.Attribute):
            name = node.func.attr

            if isinstance(node.func.value, ast.Name):
                base = node.func.value.id
            elif isinstance(node.func.value, ast.Call):
                base = self.asttok.get_text(node.func.value)
                logging.debug("node.func.value is ast.Call, Ignoring!")
            elif isinstance(node.func.value, ast.Subscript):
                base = self.asttok.get_text(node.func.value)
                # NOTE: currently, we use text of chained functions (i.e. foo().bar(), foo() is used),
                # because Python is runtime type language, and it is not possible to get the type statically
                logging.warning("node.func.value type ast.Subscript, fields: %s",
                                list(ast.iter_fields(node.func.value)))
            else:
                base = self.asttok.get_text(node.func.value)
                logging.warning("node.func.value type: %s, fields: %s",
                              type(node.func.value), list(ast.iter_fields(node.func.value)))
        else:
            # NOTE: we assume the imported functions are not redefined! this may not be true!
            if isinstance(node.func, ast.Name):
                name = node.func.id
            else:
                name = self.asttok.get_text(node.func)
                logging.warning("node.func type: %s, name: %s", type(node.func), name)
            name = self.alias2name[name] if name in self.alias2name else name
            base = self.name2module[name] if name in self.name2module else None

        # compute arguments
        args = []
        for arg_index, arg_node in enumerate(node.args):
            args.append(self.asttok.get_text(arg_node))
        for keyword_index, keyword_node in enumerate(node.keywords):
            args.append(self.asttok.get_text(keyword_node))
        if hasattr(node, 'starargs') and node.starargs is not None:
            # append '*' to reproduce the calling text
            args.append('*' + self.asttok.get_text(node.starargs))
        if hasattr(node, 'kwargs') and node.kwargs is not None:
            # append '**' to reproduce the calling text
            args.append('**' + self.asttok.get_text(node.kwargs))

        # log stuff
        if base:
            logging.warning("calling function %s.%s with args %s at line %d", base, name, args, node.lineno)
            out = {
                "Function"  : "%s.%s" % (base, name),
                "Args"		: args,
                "File"		: self.infile, 
				"Line"		: node.lineno,
            }
        else:
            logging.warning("calling function %s with args %s at line %d", name, args, node.lineno)
            out = {
                "Function"	: name,
                "Args"		: args,
                "File"		: self.infile, 
				"Line"		: node.lineno,
            }
        self.buf.append(out)
        full_name = name if base is None else '%s.%s' % (base, name)
        source_text = self.asttok.get_text(node)
        source_range = (node.first_token.start, node.last_token.end)
        if self.func_only:
            name_to_check = '.' + name if base else name
        else:
            name_to_check = full_name
        if self.declrefs_filter_set is None or name_to_check in self.declrefs_filter_set:
            self.declrefs.append((base, name, tuple(args), source_text, source_range))
        ast.NodeVisitor.generic_visit(self, node)

    def get_declrefs(self):
        return self.declrefs


class PyAnalyzer(StaticAnalyzer):
    def __init__(self):
        super(PyAnalyzer, self).__init__()
        self.language = LanguageEnum.python

    def astgen(self, inpath, outfile, root=None, configpath=None, pkg_name=None, pkg_version=None, evaluate_smt=False):
        analyze_path, is_decompress_path, outfile, root, configpath = self._sanitize_astgen_args(
            inpath=inpath, outfile=outfile, root=root, configpath=configpath, language=self.language)

        # try python2
        try:
            # load the config proto
            configpb = AstLookupConfig()
            read_proto_from_file(configpb, configpath, binary=False)
            logging.debug("loaded lookup config from %s:\n%s", configpath, configpb)
            # invoke the language specific ast generators to call functions

            # get input files
            infiles, root = self._get_infiles(inpath=analyze_path, root=root, language=self.language)

            # initialize resultpb
            resultpb = PkgAstResults()
            pkg = resultpb.pkgs.add()
            pkg.config.CopyFrom(configpb)
            pkg.pkg_name = pkg_name if pkg_name is not None else basename(analyze_path)
            if pkg_version is not None:
                pkg.pkg_version = pkg_version
            pkg.language = ast_pb2.PYTHON
            buf = []
            for infile in infiles:
                all_source = open(infile, 'r').read()
                try:
                    tree = ast.parse(all_source, filename=infile)
                except SyntaxError as se:
                    logging.warning("Syntax error %s parsing file %s in python2!", se, infile)
                    raise se
                # mark the tree with tokens information
                asttok = asttokens.ASTTokens(source_text=all_source, tree=tree, filename=infile)
                visitor = PythonDeclRefVisitor(buf=buf, infile=infile, asttok=asttok, configpb=configpb)
                visitor.visit(tree)
                logging.warning("collected functions: %s", Counter(visitor.get_declrefs()).items())

                filepb = self._get_filepb(infile, root)
                for base, name, args, source_text, source_range in visitor.get_declrefs():
                    api_result = self._get_api_result(base, name, args, source_text, source_range, filepb)
                    pkg.api_results.add().CopyFrom(api_result)

    
            logging.warning('writing to %s' % (outfile+'.json'))
            write_dict_to_file(buf, outfile + '.json')

            # save resultpb
            write_proto_to_file(resultpb, outfile, binary=False)

        # try python3
        except SyntaxError as se:
            logging.warning("Syntax error %s, now trying to parse %s again in python3!", se, analyze_path)
            astgen_py3_cmd = ['python3', 'astgen_py3.py', analyze_path, outfile, '-c', configpath]
            if root is not None:
                astgen_py3_cmd.extend(['-b', root])
            if pkg_name is not None:
                astgen_py3_cmd.extend(['-n', pkg_name])
            if pkg_version is not None:
                astgen_py3_cmd.extend(['-v', pkg_version])
            exec_command("python3 astgen", astgen_py3_cmd, cwd="static_proxy")
        except Exception as e:
            logging.error("Fatal error %s running astgen for %s!", e, analyze_path)

        # optionally evaluate smt formula
        if evaluate_smt:
            resultpb = PkgAstResults()
            read_proto_from_file(resultpb, filename=outfile, binary=False)
            satisfied = self._check_smt(astgen_results=[resultpb], configpath=configpath)
            resultpb.pkgs[0].config.smt_satisfied = satisfied
            write_proto_to_file(resultpb, filename=outfile, binary=False)

        # clean up residues
        self._cleanup_astgen(analyze_path=analyze_path, is_decompress_path=is_decompress_path)
