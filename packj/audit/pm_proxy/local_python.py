#
# Inspired from pypi.py
# Partially analysis support for local Python packages.
#
import json
import logging
import re
import os
import dateutil.parser
from os.path import join, exists

from packj.util.files import read_file_lines
from packj.util.json_wrapper import json_loads
from packj.audit.pm_proxy.pm_base import PackageManagerProxy

from pathlib import Path
import ast
import pkg_resources


def literal_eval_with_vars(node_or_string, variables):
    """
    from https://github.com/python/cpython/blob/3.11/Lib/ast.py

    Evaluate an expression node or a string containing only a Python
    expression.  The string or node provided may only consist of the following
    Python literal structures: strings, bytes, numbers, tuples, lists, dicts,
    sets, booleans, and None.

    Caution: A complex expression can overflow the C stack and cause a crash.
    """
    if isinstance(node_or_string, str):
        node_or_string = parse(node_or_string.lstrip(" \t"), mode='eval')
    if isinstance(node_or_string, ast.Expression):
        node_or_string = node_or_string.body

    def _raise_malformed_node(node):
        msg = "malformed node or string"
        if lno := getattr(node, 'lineno', None):
            msg += f' on line {lno}'
        raise ValueError(msg + f': {node!r}')

    def _convert_num(node):
        value = getattr(node, 'value', None)
        if isinstance(node, ast.Constant) or type(value) in (int, float, complex):
            return node.value
        elif variables.get(node.id):
            return variables.get(node.id)
        _raise_malformed_node(node)

    def _convert_signed_num(node):
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
            operand = _convert_num(node.operand)
            if isinstance(node.op, ast.UAdd):
                return +operand
            else:
                return -operand
        return _convert_num(node)

    def _convert(node):
        if isinstance(node, ast.Constant):
            return node.value
        elif isinstance(node, ast.Tuple):
            return tuple(map(_convert, node.elts))
        elif isinstance(node, ast.List):
            return list(map(_convert, node.elts))
        elif isinstance(node, ast.Set):
            return set(map(_convert, node.elts))
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == 'set'
            and node.args == node.keywords == []
        ):
            return set()
        elif isinstance(node, ast.Dict):
            if len(node.keys) != len(node.values):
                _raise_malformed_node(node)
            return dict(zip(map(_convert, node.keys), map(_convert, node.values)))
        elif isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Sub)):
            left = _convert_signed_num(node.left)
            right = _convert_num(node.right)
            if isinstance(left, (int, float)) and isinstance(right, complex):
                if isinstance(node.op, ast.Add):
                    return left + right
                else:
                    return left - right
        return _convert_signed_num(node)

    return _convert(node_or_string)


class SetupPyAnalyzer(ast.NodeVisitor):
    __metadata = {}

    def __init__(self):
        self.requirements = list()
        self._vars = {}

    def metadata(self):
        return self.__metadata

    def visit_Call(self, node):
        is_setup_func = False

        if node.func and type(node.func) == ast.Name:
            func: ast.Name = node.func
            is_setup_func = func.id == "setup"

        if is_setup_func:
            for kwarg in node.keywords:
                try:
                    if isinstance(kwarg.value, ast.Str):
                        self.__metadata[kwarg.arg] = ast.literal_eval(kwarg.value)
                    elif isinstance(kwarg.value, ast.Name):
                        if self._vars.get(kwarg.value.id):
                            for k, v in self._vars.get(kwarg.value.id).items():
                                self.__metadata[k] = v
                            self.generic_visit(node)
                            return
                        else:
                            self.__metadata[kwarg.arg] = '<unknown>'
                    elif isinstance(kwarg.value, ast.Call):
                        self.__metadata[kwarg.arg] = '<unknown>'
                    elif isinstance(kwarg.value, ast.Dict):
                        self.__metadata[kwarg.arg] = ast.literal_eval(kwarg.value)
                    elif isinstance(kwarg.value, ast.List):
                        self.__metadata[kwarg.arg] = ast.literal_eval(kwarg.value)
                    else:
                        print(kwarg.arg, kwarg.value)
                except Exception as e:
                    pass

        self.generic_visit(node)

    def visit_Assign(self, node):
        '''
        This is needed as poetry uses a variable to store the metadata
        and unpacks it as kwargs. eg:
        setup(**metadata)
        '''
        value = node.value
        var_name = node.targets[0].id
        if isinstance(value, ast.Dict):
            self._vars[var_name] = literal_eval_with_vars(value, self._vars)
        elif isinstance(value, ast.List):
            self._vars[var_name] = literal_eval_with_vars(value, self._vars)


def parse_setup_py(path):
    with Path(path).open() as file:
        tree = ast.parse(file.read())

    analyzer = SetupPyAnalyzer()
    analyzer.visit(tree)
    return analyzer.metadata()


class LocalPythonProxy(PackageManagerProxy):
    def __init__(self, cache_dir=None, isolate_pkg_info=False):
        super(LocalPythonProxy, self).__init__()
        self.cache_dir = cache_dir
        self.isolate_pkg_info = isolate_pkg_info
        self.metadata_format = 'json'
        self.dep_format = 'requirement'
        self.name = 'local_python'
        self._query_cache = {}

    def get_downloads(self, pkg_name, pkg_info):
        return None

    def get_metadata(self, pkg_name, pkg_version=None):
        from configparser import ConfigParser

        try:
            path = os.path.join(pkg_name, 'setup.py')
            pkg_info = parse_setup_py(path)
        except Exception as e:
            print(path)
            print(
                f'fail in get_metadata for pkg_path {pkg_name}: {str(e)} (tip: setup.py is needed)'
            )
            pkg_info = None
        finally:
            return pkg_name, pkg_info

    def __parse_string_for_dep_info(self, line):
        try:
            ver_match = re.search(r'(.*)(==|>=|<=)(.*)', line)
            if ver_match is not None:
                return ver_match.group(1), ver_match.group(3)
            else:
                return (line, None)
        except Exception as e:
            logging.debug("Failed to parse PyPI dep %s: %s" % (line, str(e)))
            return None

    def parse_deps_file(self, deps_file):
        try:
            dep_list = []
            for line in read_file_lines(deps_file):
                line = line.replace(' ', '')
                if line == '' or line.startswith('#'):
                    continue
                dep = self.__parse_string_for_dep_info(line)
                assert dep, "failed"

                dep_list.append(dep)
            return dep_list
        except Exception as e:
            logging.debug("Failed to parse PyPI deps file %s: %s" % (line, str(e)))
            return None

    def get_release_history(self, pkg_name, pkg_info=None, max_num=-1):
        return None

    def get_version(self, pkg_name, ver_str=None, pkg_info=None):
        try:
            if not pkg_info:
                _, pkg_info = self.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
            assert pkg_info, "Failed to get metadata!"

            ver_str = pkg_info.get('version', None)
            assert ver_str, "No package version string found in metadata'"

            return {
                'tag': ver_str,
            }
        except Exception as e:
            logging.warning(str(e))
            return None

    def get_description(self, pkg_name, ver_str=None, pkg_info=None):
        try:
            if not pkg_info:
                _, pkg_info = self.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
            assert pkg_info, "Failed to get metadata!"

            descr = pkg_info.get('description', None)
            if descr:
                return descr

            raise Exception('No package summary or description found in metadata')
        except Exception as e:
            logging.warning(str(e))
            return None

    def get_readme(self, pkg_name, ver_str=None, pkg_info=None):
        try:
            if not pkg_info:
                _, pkg_info = self.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
            assert pkg_info, "Failed to fetch metadata!"

            descr = pkg_info.get('description', None)
            if descr:
                return descr

            raise Exception('No package description found in metadata')
        except Exception as e:
            logging.warning(str(e))
            return None

    def get_dependencies(self, pkg_name, ver_str=None, pkg_info=None, ver_info=None):
        try:
            if not pkg_info:
                _, pkg_info = self.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
            assert pkg_info, "Failed to fetch metadata!"

            deps = pkg_info.get('requires_dist', None)
            if deps:
                return deps

            raise Exception('No dependency info found in metadata')
        except Exception as e:
            logging.warning(str(e))
            return None

    def get_download_url(self, pkg_name, ver_str=None, pkg_info=None, ver_info=None):
        return None

    def get_repo(self, pkg_name, ver_str=None, pkg_info=None, ver_info=None):
        try:
            if not pkg_info:
                _, pkg_info = self.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
            assert pkg_info, "Failed to fetch metadata!"

            repo = pkg_info.get('url', None)
            if repo:
                return repo

            raise Exception('No repo info found in metadata')
        except Exception as e:
            logging.warning(str(e))
            return None

    def get_downloads(self, pkg_name, pkg_info):
        return None

    def get_homepage(self, pkg_name, ver_str=None, pkg_info=None):
        try:
            if not pkg_info:
                _, pkg_info = self.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
            assert pkg_info, "Failed to fetch metadata!"

            homepage = pkg_info.get('homepage', None)
            if homepage:
                return homepage

            url = pkg_info.get('url', None)
            if url:
                return url

            raise Exception('No homepage info found in metadata')
        except Exception as e:
            logging.warning(str(e))
            return None

    def __get_email_list(self, data):
        data = data.replace(' ', '')
        if isinstance(data, list):
            return data
        elif isinstance(data, str):
            if ',' in data:
                return data.split(',')
            elif ' ' in data:
                return data.split(' ')
            elif ';' in data:
                return data.split(';')
            else:
                return [data]
        else:
            raise Exception('error parsing author email!')

    def get_maintainers(self, pkg_name, ver_str=None, pkg_info=None, ver_info=None):
        return None

    def get_author(self, pkg_name, ver_str=None, pkg_info=None, ver_info=None):
        try:
            if not pkg_info:
                _, pkg_info = self.get_metadata(pkg_name=pkg_name, pkg_version=ver_str)
            assert pkg_info, "Failed to fetch metadata!"

            author = pkg_info.get('author', None)
            author_email = pkg_info.get('author_email', None)

            email_list = self.__get_email_list(author_email)
            if not email_list:
                return None

            ret = []
            for email in email_list:
                ret.append({'email': email})
            return ret
        except Exception as e:
            logging.warning(
                "Failed to get author for PyPI package %s: %s" % (pkg_name, str(e))
            )
            return None


def test():
    import sys
    import json

    p = LocalPythonProxy()
    m = p.get_metadata(pkg_name=sys.argv[1])
    print(json.dumps(m, indent=4))


if __name__ == "__main__":
    test()
