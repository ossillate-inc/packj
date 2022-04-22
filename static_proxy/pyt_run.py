# TODO: 1. imports, 2. finish updating CSV, 3. base types and args (ast visiting) in summary, 4. instantiable
import os
import ast
import json
import logging
import tempfile
import asttokens
import proto.python.ast_pb2 as ast_pb2

from os.path import basename, dirname
from proto.python.ast_pb2 import AstNode, AstLookupConfig, FileInfo
from proto.python.module_pb2 import ModuleResult, ModuleSummary, ModuleStatic
from util.job_util import read_proto_from_file, write_proto_to_file, exec_command


class PythonVisitor(ast.NodeVisitor):
    def __init__(self, asttok):
        self.asttok = asttok
        self.calling_func = None

    def get_calling_func(self):
        return self.calling_func

    def specify_search(self, lineno, sensitive_api, arglist, is_original_api_call):
        self.lineno = lineno
        self.sensitive_api = sensitive_api
        # api used may be full name or func name, but AST parser only looking for func name, so split on dots to get func name
        name_components = sensitive_api.split(".")
        self.sensitive_api_func_name = name_components[-1]
        self.arglist = arglist
        self.is_original_api_call = is_original_api_call #if false, looking for api call's CALLING FUNCTION

    def visit_FunctionDef(self, node):
        if not self.is_original_api_call:
            body = node.body
            for statement in body:
                if statement.lineno == self.lineno:
                    self.calling_func = node.name
                    args = self.asttok.get_text(node.args)
                    arg_components = args.split(",")
                    for arg in arg_components:
                        self.arglist.append(arg.strip())
        ast.NodeVisitor.generic_visit(self, node)  # TODO: not sure if this is necessary or redundant

    def visit_Call(self, node):
        if self.is_original_api_call:
            if self.lineno == node.lineno:
                if self.sensitive_api == node.func.attr:
                    for arg_index, arg_node in enumerate(node.args):
                        self.arglist.append(self.asttok.get_text(arg_node))
        ast.NodeVisitor.generic_visit(self, node)  # TODO: not sure if this is necessary or redundant


class Source:
    def __init__(self, source, trigger_word):
        self.label = source['label']
        self.line_number = source['line_number']
        self.path = source['path']
        self.sensitive_api = trigger_word


class Sink:
    def __init__(self, sink, trigger_word):
        self.label = sink['label']
        self.line_number = sink['line_number']
        self.path = sink['path']
        self.sensitive_api = trigger_word


class Vulnerability:
    def __init__(self, source, source_trigger_word, sink, sink_trigger_word, type, reassignment_nodes):
        self.source_obj = Source(source, source_trigger_word)
        self.sink_obj = Sink(sink, sink_trigger_word)
        self.type = type
        self.reassignment_nodes = reassignment_nodes


def get_source_node(src, apis, source_dict, vuln_files_ASTs):
    source_node = AstNode()

    # search apis dictionary to find source_node.name in values
    # invocation detail
    source_node.type = AstNode.FUNCTION_DECL_REF_EXPR
    #source_node.name = next(entry.name for entry in config.apis if entry.id == id)

    temp = src.sensitive_api
    stripped_name = temp.replace('(', '').replace('[', '')
    source_node.name = stripped_name
    id = -1
    for key, val in source_dict.items():
        if source_node.name in val:
            id = key

    source_node.full_name = next(entry.full_name for entry in apis if entry.id == id)
    source_node.base_type = next(entry.base_type for entry in apis if entry.id == id)
    source_node.id = id
    source_node.source_type = next(entry.source_type for entry in apis if entry.id == id)

    # use ast to parse out arguments
    tree, asttok = vuln_files_ASTs[src.path]
    visitor = PythonVisitor(asttok=asttok)
    src_arglist = []
    visitor.specify_search(src.line_number, src.sensitive_api, src_arglist, True)
    visitor.visit(tree)
    source_node.arguments.extend(src_arglist)

    # source code location
    source_file_info = FileInfo()
    source_file_info.filename = basename(src.path)
    source_file_info.relpath = dirname(src.path)
    source_node.range.start.row = src.line_number
    # source_node.range.start.column = 20 # OPTIONAL
    source_node.range.start.file_info.CopyFrom(source_file_info)
    source_node.range.end.row = src.line_number
    # source_node.range.end.column = 40 # OPTIONAL
    source_node.range.end.file_info.CopyFrom(source_file_info)
    return source_node


def get_sink_node(snk, apis, sink_dict, vuln_files_ASTs):
    sink_node = AstNode()
    # invocation detail
    sink_node.type = AstNode.FUNCTION_DECL_REF_EXPR

    temp = snk.sensitive_api
    stripped_name = temp.replace('(', '').replace('[', '')
    sink_node.name = stripped_name
    id = -1
    for key, val in sink_dict.items():
        #print "sink_node.name = ", sink_node.name
        #print "name = ", val
        if sink_node.name in val:
            id = key

    sink_node.full_name = next(entry.full_name for entry in apis if entry.id == id)
    sink_node.base_type = next(entry.base_type for entry in apis if entry.id == id)
    sink_node.id = id
    sink_node.sink_type = next(entry.sink_type for entry in apis if entry.id == id)

    # use ast to parse out arguments
    tree, asttok = vuln_files_ASTs[snk.path]
    visitor = PythonVisitor(asttok=asttok)
    snk_arglist = []
    visitor.specify_search(snk.line_number, snk.sensitive_api, snk_arglist, True)
    visitor.visit(tree)
    sink_node.arguments.extend(snk_arglist)

    # source code location
    sink_file_info = FileInfo()
    sink_file_info.filename = basename(snk.path)
    sink_file_info.relpath = dirname(snk.path)
    sink_node.range.start.row = snk.line_number
    # sink_node.range.start.column = 8 # OPTIONAL
    sink_node.range.start.file_info.CopyFrom(sink_file_info)
    sink_node.range.end.row = snk.line_number
    # sink_node.range.end.column = 100 # OPTIONAL
    sink_node.range.end.file_info.CopyFrom(sink_file_info)
    return sink_node


def get_propagate_node(label, line_number, path):
    propagate_node = AstNode()
    #propagate_node.type =
    propagate_node.name = label
    # source code location
    propagate_file_info = FileInfo()
    propagate_file_info.filename = basename(path)
    propagate_file_info.relpath = dirname(path)
    propagate_node.range.start.row = line_number
    propagate_node.range.start.file_info.CopyFrom(propagate_file_info)
    propagate_node.range.end.row = line_number
    propagate_node.range.end.file_info.CopyFrom(propagate_file_info)
    return propagate_node


def get_mock_danger_node():
    danger_node = AstNode()
    return danger_node


def set_result(result, apis, source_dict, sink_dict, vuln_nodes, vuln_files_ASTs):
    for node in vuln_nodes:
        # skip package_info for now
        source_node = get_source_node(node.source_obj, apis, source_dict, vuln_files_ASTs)
        sink_node = get_sink_node(node.sink_obj, apis, sink_dict, vuln_files_ASTs)
        flow = result.flows.add()
        flow.source.CopyFrom(source_node)
        flow.sink.CopyFrom(sink_node)

        for rnode in node.reassignment_nodes:
            propagate_node = get_propagate_node(rnode["label"], rnode["line_number"], rnode["path"])
            flow.hops.add().CopyFrom(propagate_node)

        #danger_node = get_mock_danger_node()
        #danger = result.dangers.add()
        #danger.danger.CopyFrom(danger_node)


def set_summary(summary, apis, source_dict, sink_dict, vuln_nodes, vuln_files_ASTs):
    for node in vuln_nodes:
        # skip package_info for now
        # there is no id for new sources

        # if file is setup.py and is in root dir of package, skip summary
        src_path = node.source_obj.path
        snk_path = node.sink_obj.path
        src_head, src_filename = os.path.split(src_path)
        snk_head, snk_filename = os.path.split(snk_path)
        src_head2, src_file_dir = os.path.split(src_head)
        snk_head2, snk_file_dir = os.path.split(snk_head)
        if src_filename == "setup.py" and snk_filename == "setup.py":
            continue

        # use ast visitor to get calling function
        tree, asttok = vuln_files_ASTs[node.source_obj.path]
        source_visitor = PythonVisitor(asttok=asttok)
        source_arglist = []
        source_visitor.specify_search(node.source_obj.line_number, node.source_obj.sensitive_api, source_arglist, False)
        source_visitor.visit(tree)
        source_calling_func_name = source_visitor.get_calling_func()
        if not source_calling_func_name:
            continue
        source = summary.sources.add()
        source.node.type = AstNode.FUNCTION_DECL
        source.node.name = source_calling_func_name
        source.node.full_name = "???"
        source.node.base_type = "???"
        source.node.arguments.extend(source_arglist)
        # TODO: set the source range for source.node
        reachable_old_source = source.reachable_sources.add()
        reachable_old_source.CopyFrom(get_source_node(node.source_obj, apis, source_dict, vuln_files_ASTs))

        # use ast visitor to get calling function
        tree, asttok = vuln_files_ASTs[node.source_obj.path]
        sink_visitor = PythonVisitor(asttok=asttok)
        sink_arglist = []
        sink_visitor.specify_search(node.sink_obj.line_number, node.sink_obj.sensitive_api, sink_arglist, False)
        sink_visitor.visit(tree)
        sink_calling_func_name = sink_visitor.get_calling_func()
        if not sink_calling_func_name:
            continue

        # the add() function returns reference
        sink = summary.sinks.add()
        sink.node.type = AstNode.FUNCTION_DECL
        sink.node.name = sink_calling_func_name
        sink.node.full_name = "???"
        sink.node.base_type = "???"
        sink.node.arguments.extend(sink_arglist)
        # TODO: set the source range for sink.node
        reachable_old_sink = sink.reachable_sinks.add()
        reachable_old_sink.CopyFrom(get_sink_node(node.sink_obj, apis, sink_dict, vuln_files_ASTs))


def reformat(apis_file, json_result_file, outfile):
    try:
        results = json.load(open(json_result_file, 'r'))
    except Exception as e:
        logging.error("failed to load pyt results in json: %s", json_result_file)
        return None

    # load the astgen config from file
    config = AstLookupConfig()
    read_proto_from_file(config, apis_file, binary=False)
    logging.warning("loaded config with %d apis to check!", len(config.apis))

    # convert list of apis into dictionary with key=id, value=full_name for easier identification
    source_dict = {}
    sink_dict = {}
    for entry in config.apis:
        # FIXME: should we support func_only mode
        if entry.functionality == ast_pb2.SOURCE:
            source_dict[entry.id] = entry.full_name
        elif entry.functionality in (ast_pb2.SINK, ast_pb2.DANGER):
            sink_dict[entry.id] = entry.full_name

    nodes = []
    # dictionary with key=name of file within package found to contain vulnerabilities and value=tuple of (tree, asttok, visitor) for that file
    vuln_files_ASTs = {}
    for entry in results['vulnerabilities']:
        source = entry['source']
        # source['label'], source['line_number'], source['path']
        source_trigger_word = entry['source_trigger_word']
        sink = entry['sink']
        # sink['label'], sink['line_number'], sink['path']
        sink_trigger_word = entry['sink_trigger_word']
        api_type = entry['type']
        reassignment_nodes = entry['reassignment_nodes']
        # of type dict
        vuln_files_ASTs[source['path']] = ()
        vuln_files_ASTs[sink['path']] = ()
        nodes.append(Vulnerability(source, source_trigger_word, sink, sink_trigger_word, api_type, reassignment_nodes))

    # initiate AST visitors (one tree per vulnerable file within package)
    for file in vuln_files_ASTs:
        src_ast = open(file, 'r').read()
        tree = ast.parse(src_ast, filename=file)
        asttok = asttokens.ASTTokens(source_text=src_ast, tree=tree, filename=file)
        # visitor = PythonVisitor(asttok=asttok)
        visit_info = (tree, asttok)
        vuln_files_ASTs[file] = visit_info

    # initialize result and summary
    result = ModuleResult()
    set_result(result, config.apis, source_dict, sink_dict, nodes, vuln_files_ASTs)
    summary = ModuleSummary()
    set_summary(summary, config.apis, source_dict, sink_dict, nodes, vuln_files_ASTs)
    static = ModuleStatic()
    static.flows.MergeFrom(result.flows)
    static.dangers.MergeFrom(result.dangers)
    static.sources.MergeFrom(summary.sources)
    static.sinks.MergeFrom(summary.sinks)
    static.taint_wrappers.MergeFrom(summary.taint_wrappers)
    write_proto_to_file(proto=static, filename=outfile, binary=False)


def ast_to_trigger_words(config_path, trigger_words_path):
    config = AstLookupConfig()
    read_proto_from_file(config, config_path, binary=False)
    source_set = set()
    sink_set = set()
    for api in config.apis:
        # TODO: add support for instantiable field in API comparison
        if api.functionality == ast_pb2.SOURCE:
            if config.func_only:
                source_set.add(api.name + "(")
            else:
                source_set.add(api.full_name + "(")
        elif api.functionality in (ast_pb2.SINK, ast_pb2.DANGER):
            if config.func_only:
                sink_set.add(api.name + "(")
            else:
                sink_set.add(api.full_name + "(")

    trigger_words = {}
    trigger_words["sources"] = list(source_set)
    trigger_words["sinks"] = {key: {} for key in sink_set}
    json.dump(trigger_words, open(trigger_words_path, 'w'), indent=2)


def pyt_run(pkg_path, config_path, out_path):
    # Convert astgen_python_smt.config to pyt trigger words file
    logging.warning("Generating all_trigger_words.pyt file from input config file")
    temp_trigger_words_path = tempfile.NamedTemporaryFile(suffix=".pyt")
    ast_to_trigger_words(config_path=config_path, trigger_words_path=temp_trigger_words_path.name)

    # Run PyT on given package, output JSON-formatted results
    logging.warning("Running PyT analysis on %s with pyt config %s", pkg_path, temp_trigger_words_path.name)
    temp_result_path = tempfile.NamedTemporaryFile(suffix=".json")
    pyt_cmd = ['python3.6', '-m', 'pyt', '-o', temp_result_path.name, '-t', temp_trigger_words_path.name, '-j', '-r', pkg_path]
    exec_command('python3.6 -m pyt', pyt_cmd)

    # Format PyT (.json) results into proper protobuf outputs
    logging.warning("Converting results in %s to protobuf format", temp_result_path.name)
    reformat(apis_file=config_path, json_result_file=temp_result_path.name, outfile=out_path)
