from packj.util.json_wrapper import json_loads
from packj.util.job_util import md5_digest_file
import os

def dir_file_count_and_size(path:str):
	from pathlib import Path
	stats = [p.stat().st_size for p in Path(path).rglob('*')]
	return len(stats), sum(stats)

def are_files_diff(file1_path, file2_path):
	if not os.path.exists(file1_path) or not os.path.exists(file2_path):
		return None
	# compare file sizes
	file1_size = os.path.getsize(file1_path)
	file2_size = os.path.getsize(file2_path)
	delta = file1_size - file2_size
	if delta:
		return delta, None

	# same size, use md5
	file1_md5 = md5_digest_file(file1_path)
	file2_md5 = md5_digest_file(file2_path)
	return delta, file1_md5 != file2_md5
	
def get_file_type(filepath):
	if os.path.isfile(filepath):
		file_type = 'FILE'
	elif os.path.isdir(filepath):
		file_type = 'DIR'
	elif os.path.islink(filepath):
		file_type = 'LINK'
	else:
		file_type = 'UNKNOWN'
	return file_type

# source: https://stackoverflow.com/questions/66994282/building-tree-structure-from-a-list-of-string-paths
class TreeNode:
	def __init__(self, name, parent):
		self.parent = parent
		self.name = name
		self.children = []

	def add_child(self, node):
		self.children.append(node)
		return node

	def print(self, is_root, handler=None, handler_args=None):
		pre_0 = "    "
		pre_1 = "│   "
		pre_2 = "├── "
		pre_3 = "└── "

		tree = self
		prefix = pre_2 if tree.parent and id(tree) != id(tree.parent.children[-1]) else pre_3

		while tree.parent and tree.parent.parent:
			if tree.parent.parent and id(tree.parent) != id(tree.parent.parent.children[-1]):
				prefix = pre_1 + prefix
			else:
				prefix = pre_0 + prefix
			tree = tree.parent

		# dump name
		name = self.name
		if is_root:
			node = '/'
		else:
			node = prefix + name

		if not handler:
			print(node)
			stop = False
		else:
			stop, handler_args = handler(prefix, name, is_root, **handler_args)
		if not stop:
			for child in self.children:
				child.print(False, handler=handler, handler_args=handler_args)

def find_and_insert(parent, edges):
	# Terminate if there is no edge
	if not edges:
		return
	
	# Find a child with the name edges[0] in the current node
	match = [tree for tree in parent.children if tree.name == edges[0]]
	
	# If there is already a node with the name edges[0] in the children, set "pointer" tree to this node. If there is no such node, add a node in the current tree node then set "pointer" tree to it
	tree = match[0] if match else parent.add_child(TreeNode(edges[0], parent))
	
	# Recursively process the following edges[1:]
	find_and_insert(tree, edges[1:])

def read_file_lines(filename):
	try:
		with open(filename, 'r') as f:
			for line in f.readlines():
				line = line.strip()
				yield line
			f.close()
	except Exception as e:
		raise Exception("Failed to read file %s: %s" % (filename, str(e)))

# loads @data from @filename
def read_dict_from_file(filename):
	try:
		data = {}
		with open(filename, 'r') as f:
			data = eval(f.read())
			f.close()
		return data
	except Exception as e:
		raise Exception("Failed to read dict from file %s: %s" % (filename, str(e)))

def read_json_from_file(filepath):
	try:
		import json
	except ImportError as e:
		raise Exception("'json' module not available. Please install.")
	try:
		with open(filepath, "r") as f:
			return json_loads(f.read())
	except Exception as e:
		raise Exception("Failed to load json data from file %s: %s" % (filepath, str(e)))

def read_from_csv(filename, skip_header=False):
	import csv
	with open(filename, 'r') as csvfile:
		reader = csv.reader(csvfile, delimiter=',')
		if skip_header:
			next(reader)
		for row in reader:
			if len(row) and not row[0].startswith('#'):
				yield row

def write_json_to_file(filepath, data_json, indent=0):
	try:
		import json
	except ImportError as e:
		raise Exception("'json' module not available. Please install.")
	try:
		with open(filepath, "w+") as f:
			json.dump(data_json, f, indent=indent)
	except Exception as e:
		raise Exception("Failed to dump json content to file %s: %s" % (filepath, str(e)))

def write_to_file(filename, data):
	try:
		with open(filename, 'w+') as f:
			f.write("%s" % (data))
	except Exception as e:
		raise Exception("Failed to write to file %s: %s" % (filename, str(e)))
