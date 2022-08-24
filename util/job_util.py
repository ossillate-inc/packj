import glob
import json, logging
import os
import hashlib
import sys
import signal
from subprocess import PIPE, Popen
from google.protobuf.text_format import MessageToString, Merge
from google.protobuf.json_format import MessageToJson
from func_timeout import func_timeout, FunctionTimedOut


"""
Helper functions
"""
def is_exe(fpath):
	return os.path.isfile(fpath) and os.access(fpath, os.X_OK)


def is_ascii(s):
	return all(ord(c) < 128 and ord(c) > 20 for c in s)


def md5_digest(s):
	import hashlib
	return hashlib.md5(s.encode('utf-8')).digest()

def md5_digest_int(s):
	import hashlib
	return int(hashlib.md5(s.encode('utf-8')).hexdigest(), 16)


def md5_digest_str(s):
	import binascii
	return binascii.hexlify(md5_digest(s))

def md5_digest_last_64bits(s):
	return md5_digest(s)[:8]


def md5_digest_last_64bits_str(s):
	return md5_digest_str(s)[:16]


def md5_digest_last_64bits_int(s):
	return int(md5_digest_last_64bits_str(s), 16)

def md5_digest_file(filepath):
	import hashlib
	return hashlib.md5(open(filepath,'rb').read()).hexdigest()

def is_mounted(path):
	with open('/proc/self/mountinfo') as file:
		line = file.readline().strip()
		while line:
			if f'{ path }' in line:
				return line.split()[3]
			line = file.readline().strip()
	return None

def in_docker():
	return is_mounted('/docker/containers/')

def exec_command(cmd, args, cwd=None, env=None, timeout=600, redirect_mask:int=0):
	"""
	Executes shell command
	redirect_mask: stdin | stdout | stderr
	"""
	current_subprocs = set()
	shutdown = False

	stdout = None
	stderr = None
	stdin = None
	err_code = None

	def handle_signal(signum, frame):
		# send signal recieved to subprocesses
		for proc in current_subprocs:
			if proc.poll() is None:
				proc.send_signal(signum)

	try:
		signal.signal(signal.SIGINT, handle_signal)
		signal.signal(signal.SIGTERM, handle_signal)

		if redirect_mask & 4:
			stdin = PIPE
		if redirect_mask & 2:
			stdout = PIPE
		if redirect_mask & 1:
			stderr = PIPE

		pipe = Popen(args, cwd=cwd, env=env, stdin=stdin, stdout=stdout, stderr=stderr)
		current_subprocs.add(pipe)
		try:
			stdout, stderr = func_timeout(timeout, pipe.communicate)
		except FunctionTimedOut as ft:
			current_subprocs.remove(pipe)
			raise Exception(f'{cmd} timed out after {timeout} seconds!')

		err_code = pipe.returncode
		if stdout and isinstance(stdout, bytes):
			stdout = stdout.decode().strip()
		if stderr and isinstance(stderr, bytes):
			stderr = stderr.decode().strip()

	except Exception as e:
		logging.debug(f'{cmd} subprocess failed {str(e)}')
		err_code = -1

	finally:
		return stdout, stderr, err_code

"""
Utilities for file system
"""
def list_recursive(indir, prefix=None, suffix=None):
	files_to_aggregate = []  # used to record files with distinct URIs
	for dirName, subdirList, fileList in os.walk(indir):
		for fname in fileList:
			filepath = os.path.join(dirName, fname)
			if prefix and fname.startswith(prefix):
				files_to_aggregate.append(filepath)
			elif suffix and fname.endswith(suffix):
				files_to_aggregate.append(filepath)
			elif not prefix and not suffix:
				files_to_aggregate.append(filepath)
	return files_to_aggregate


def list_recursive_unique_filename(indir, prefix=None, suffix=None):
	fname2filepath = {}  # used to record files with distinct filenames
	for dirName, subdirList, fileList in os.walk(indir):
		for fname in fileList:
			filepath = os.path.join(dirName, fname)
			if prefix and fname.startswith(prefix):
				fname2filepath[fname] = filepath
			if suffix and fname.endswith(suffix):
				fname2filepath[fname] = filepath
			elif not prefix and not suffix:
				fname2filepath[fname] = filepath
	return fname2filepath


"""
Utilities for protocol buffer IO
"""
def write_proto_to_file(proto, filename, binary=True):
	if binary:
		f = open(filename, "wb")
		f.write(proto.SerializeToString())
		f.close()
	else:
		f = open(filename, "w")
		f.write(MessageToJson(proto))
		f.close()


def write_proto_to_string(proto, binary=True):
	if binary:
		return proto.SerializeToString()
	else:
		return MessageToString(proto)


def read_proto_from_file(proto, filename, binary=True):
	if binary:
		f = open(filename, "rb")
		proto.ParseFromString(f.read())
		f.close()
	else:
		f = open(filename, "r")
		Merge(f.read(), proto)
		f.close()


def read_proto_from_string(proto, content_string, binary=True):
	if binary:
		proto.ParseFromString(content_string)
	else:
		Merge(content_string, proto)

def write_dict_to_file(dict_data, outfile):
	import json
	with open(outfile, 'w+') as of:
		json.dump(dict_data, of, indent=4)
