#!/usr/bin/python

#
# Based on https://github.com/dirtyharrycallahan/pystrace
#

import json
import os
import sys
import tempfile

from packj.audit.strace_parser.strace import *
from packj.audit.strace_parser.strace_utils import *

#
# strace usage: strace -f -ttt -T -o strace.log <cmd>
#
from packj.audit.strace_parser.syscalls import syscall_table

def parse_network_activity(summary:dict):
	port2service = {
		53  : 'DNS',
		443 : 'HTTPS',
		80	: 'HTTP',
		22  : 'SSH'
	}
 
	assert summary, "no input"

	data = summary.get('network', None)
	if not data:
		return None

	port_regex = r' sin_port=htons\((\d+)\)'

	network_summary = {
		'connect' : []
	}
	for rec in data:
		#print(rec)
		if rec['msg'] == 'Connection attempted' and 'ip_address' in rec:
			port_text = rec['info'].split(',')[1]
			match = re.findall(port_regex, port_text)
			if match:
				key = port2service.get(int(match[0]), None)
			else:
				key = f'port:{key}'
			if 'domain' in rec:
				val = rec['domain']
			else:
				val = rec['ip_address']
			if {key:val} not in network_summary['connect']:
				network_summary['connect'].append({key:val})
	#print(network_summary)
	return network_summary

def parse_filesystem_activity(summary:dict):
	assert summary, "no input"

	data = summary.get('files', None)
	if not data:
		return None

	filesystem_summary = {}
	return filesystem_summary

def parse_trace_file(input_file, tempdir):
	infile = open(input_file, "r")
	strace_stream = StraceInputStream(infile)

	summary = {}
	for entry in strace_stream:
		ts = entry.timestamp
		name = entry.syscall_name

		try:
			return_value = int(entry.return_value)
		except:
			#print(f"Invalid return value: {entry.return_value}")

			# permit syscalls that do not depend on return_value
			if 'exit' in name:
				return_value = entry.return_value
			else:
				continue
		
		if name in ['newfstatat', 'EXIT']:
			continue

		num_args = len(entry.syscall_arguments)
		args = []

		for idx in range(num_args):
			arg = array_safe_get(entry.syscall_arguments, idx)
			args.append(arg)

		args_str = ','.join(args)

		syscall_info = syscall_table.get(name.upper(), None)
		if not syscall_info:
			continue

		parser = syscall_info.get("parser", None) 
		category = syscall_info.get("category", None)
		if parser and category:
			data = parser(ts, name, args_str, args, return_value)
			if not data:
				continue
			if category not in summary:
				summary[category] = []
			summary[category].append(data)	  

	infile.close()
	strace_stream.close()

	try:
		_, summary_filepath = tempfile.mkstemp(prefix='summary_', dir=tempdir, suffix='.json')
		with open(summary_filepath, mode='w+') as f:
			f.write(json.dumps(summary, indent=4))
		os.chmod(summary_filepath, 0o444)
	except Exception as e:
		logging.debug(f'Failed to generate trace summary file: {str(e)}')

	return summary

if __name__ == "__main__":
	input_file = sys.argv[1]
	parse_trace_file(input_file)
