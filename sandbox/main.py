#!/usr/bin/env python

from __future__ import print_function

import sys
import os
import inspect
import logging
import yaml
import tempfile
import ipaddress
import shutil

from colorama import Fore, Style

from util.net import ipv4_to_ipv6
from util.formatting import human_format
from util.job_util import exec_command, md5_digest_file
from util.files import read_from_csv, get_file_type, are_files_diff
from util.files import TreeNode, find_and_insert, dir_file_count_and_size

def add_process_rule(key, val):
	assert key in ['allow', 'block'], f'invalid {category} rule {k}, supported allow/block'
	return f'\t{key}:{val}\n'

def add_fs_rule(key, val):
	assert key in ['allow', 'block'], f'invalid {category} rule {k}, supported allow/block'
	if key == 'block': key = 'hide'
	return f'\t{key}:{val}\n'

def add_network_rule(key, val, port='*', domain='unknown'):
	assert key in ['allow', 'block'], f'invalid {category} rule {k}, supported allow/block/kill'
	if key == 'block': key = 'kill'
	ipv4_addr_list = []
	ipv6_addr_list = []
	if val and ':' in val:
		val, port = val.split(':')
	try:
		ipaddress.ip_address(val)
		try:
			ipaddress.IPv4Address(val)
			ipv4_addr_list.append((val, port, domain, 'v4'))
			ip_addr = ipv4_to_ipv6(val)
			if (ip_addr):
				ipv6_addr_list.append((ip_addr, port, domain, 'v6'))
		except ValueError:
			ipaddress.IPv6Address(val)
			ipv6_addr_list.append((val, port, domain, 'v6'))

	except Exception as e:
		import socket
		logging.debug(f'{val} is not a valid IP address ({str(e)}), resolving {val}')
		res = socket.getaddrinfo(val, None)
		if not res:
			raise Exception(f'{val} not a valid IP/domain address')
		domain = val
		for r in res:
			try:
				# format: (family, type, proto, canonname, sockaddr)
				family, typ, proto, canonname, sockaddr = r
				assert family and sockaddr
				if family == socket.AF_INET6:
					ip_addr, _, _, _ = sockaddr
					assert ip_addr
					ipv6_addr_list.append((ip_addr, port, domain, 'v6'))
				elif family == socket.AF_INET:
					ip_addr, _ = sockaddr
					assert ip_addr
					ipv4_addr_list.append((ip_addr, port, domain, 'v4'))
			except Exception as e:
				logging.debug(f'Failed to parse network rule {key}:{val} : {str(e)}')

	return ''.join([f'\t{key}:{ip_addr}:{port}#{typ},{domain}\n' for ip_addr, port, domain, typ in set(ipv4_addr_list+ipv6_addr_list)])

rule_parsers = {
		'fs'		: add_fs_rule,
		'network'	: add_network_rule,
		'process'	: add_process_rule,
}

def build_sandboxing_profile(pm, filename='packj.yaml'):
	try:
		from util.net import get_dns_ips
		with open(filename) as f:
			config_data = yaml.safe_load(f)

		rules = ''
		if 'sandbox' in config_data and 'rules' in config_data['sandbox'] and config_data['sandbox']['rules']:
			for category,category_data in config_data['sandbox']['rules'].items():
				rule_parser = rule_parsers.get(category, None)
				assert rule_parser, f'invalid category: {category}'

				rules += f'[{category}]:\n'
				for key, val in category_data.items():
					val = val.replace(' ','').split(',')
					logging.debug(f'Adding {category} rule {key} : {val}')
					if isinstance(val, str):
						rules += rule_parser(key, val)
					elif isinstance(val, list):
						for v in val:
							rules += rule_parser(key, v)
					else:
						raise Exception(f'{type(val)} element under {key} is not allowed!')

			# add DNS rule
			dns_ips = get_dns_ips()
			assert dns_ips and isinstance(dns_ips, list), 'invalid DNS'
			logging.debug(f'Allowing {len(dns_ips)} DNS servers: {dns_ips}')
			for dns_ip in dns_ips:
				rules += rule_parsers['network']('allow', dns_ip, domain='DNS')
		return rules
	except Exception as e:
		print(f'Failed to parse rules in {filename}: {str(e)}')
		exit(1)

def parse_network_event(net_events, event_data):
	try:
		event_type, domain, ipaddr, port, ipaddr_type, rule = event_data
		if ipaddr_type == 'v6':
			ipaddr_type = 'IPv6'
		else:
			ipaddr_type = 'IPv4'
		if not domain:
 			key = (ipaddr, port, rule, ipaddr_type)
		else:
			key = (domain, port, rule, ipaddr_type)
		if key not in net_events:
			net_events[key] = set()
		net_events[key].add(ipaddr)
	except Exception as e:
		logging.error(f'Ignoring erroneus network event {event_data}: {str(e)}')
	finally:
		return net_events

def parse_filesystem_event(fs_events, fs_tree_root, event_data):
	try:
		event_type, filepath, file_size, file_type = event_data

		if event_type == "open":
			find_and_insert(fs_tree_root, filepath.split(os.sep)[1:])
		else:
			file_status = "deleted"

		#if filepath not in fs_events:
		#	fs_events[filepath] = (file_status, file_size, file_type)

	except Exception as e:
		logging.error(f'Ignoring erroneus filesystem event {event_data}: {str(e)}')
	finally:
		return fs_events, fs_tree_root

# parse log
def parse_sandbox_log(sandbox_root, sandbox_log):
	try:
		net_events = {}
		fs_events = {}

		fs_tree_root = TreeNode(sandbox_root, None)
		assert fs_tree_root, "couldn't build filesystem tree"

		for event_data in read_from_csv(sandbox_log):
			event_type = event_data[0]

			# network connections
			if event_type in ['connect']:
				net_events = parse_network_event(net_events, tuple(event_data))

			# new files
			elif event_type in ['open', 'unlink']:
				fs_events, fs_tree_root = parse_filesystem_event(fs_events, fs_tree_root, tuple(event_data))

		return fs_events, fs_tree_root, net_events

	except Exception as e:
		raise Exception(f'error parsing events: {str(e)}')

def dump_net_events(net_events, details=False):
	try:
		print(f'{Style.BRIGHT}[+] Network connections{Style.RESET_ALL}')
		for key, val_list in net_events.items():
			domain_or_ipaddr, port, rule, ipaddr_type = key
			if not rule:
				rule_msg = f'{ipaddr_type} rules not supported'
			elif rule == 'ALLOW':
				rule_msg = f'{Fore.GREEN}ALLOW{Style.RESET_ALL}'
			else:
				rule_msg = f'{Fore.RED}BLOCK{Style.RESET_ALL}'
			if len(val_list):
				print(f'\t[+] {Fore.BLUE}{domain_or_ipaddr}{Style.RESET_ALL} ({len(val_list)} {ipaddr_type} addresses) at port {port} [rule: {rule_msg}]')
			else:
				print(f'\t[+] {Fore.BLUE}{domain_or_ipaddr}{Style.RESET_ALL} ({ipaddr_type} address) at port {port} [rule: {rule_msg}]')
			if details:
				for ipaddr in list(val_list):
					print(f'\t\t[+] {ipaddr} ')
	except Exception as e:
		raise Exception(f'error dumping network activity: {str(e)}')

# dump name and attributes
def dump_file_attributes(prefix, name, is_root, details=None, host_path=None, sandbox_path=None, fs_changes=None):

	args = {'details':details, 'fs_changes':fs_changes}
	if details:
		print(name+prefix)
		return False, args

	# sandbox FS absolute path
	if not sandbox_path:
		sandbox_path = name
	else:
		sandbox_path = os.path.join(sandbox_path, name)
	assert os.path.exists(sandbox_path), f'"{sandbox_path}" does not exist'

	# host FS absolute path
	if not host_path:
		host_path = name = '/'
	else:
		host_path = os.path.join(host_path, name)

	# file type
	file_type  = get_file_type(sandbox_path)
	file_size = os.path.getsize(sandbox_path)

	# prefix
	node = ''
	if not is_root:
		node = prefix

	# followed by name (color-coded)
	if file_type == 'DIR':
		node += f'{Fore.BLUE}{name}{Style.RESET_ALL}'
	else:
		node += name

	new = not os.path.exists(host_path)
	args.update({'sandbox_path':sandbox_path, 'host_path': host_path})

	if not is_root and not details:

		# detect new and modified files
		if new:
			node += f' [{Fore.GREEN}new{Style.RESET_ALL}: {file_type}'
			if file_type == 'FILE':
				node += f', {human_format(file_size)} bytes'
			else:
				file_count, dir_size = dir_file_count_and_size(sandbox_path)
				node += f', {file_count} files, {human_format(dir_size)} bytes'
			node += ']'

		elif file_type != 'DIR':
			# compare file sizes
			size_delta, md5_diff = are_files_diff(sandbox_path, host_path)
			if size_delta:
				node += f' [{Fore.RED}modified{Style.RESET_ALL} {file_type}:'
				if size_delta < 0:
					node += ' -'
				else:
					node += ' +'
				node += f'{human_format(abs(size_delta))} bytes]'
			elif md5_diff:
				node += f' [{Fore.RED}modified{Style.RESET_ALL} {file_type}:]'
	print(node)

	# traverse deeper
	if new and host_path not in fs_changes:
		fs_changes.append((sandbox_path, host_path, file_type, new))
	return new, args

def dump_fs_events(fs_events, fs_tree_root, details=False):
	try:
		print(f'{Style.BRIGHT}[+] Filesystem changes{Style.RESET_ALL}')

		fs_changes = []
		args = {'details':details, 'fs_changes':fs_changes}
		fs_tree_root.print(True, handler=dump_file_attributes, handler_args=args)

		# TODO: show deleted files
		#for key, val_tuple in fs_events.items():
		#	file_status, file_size, file_type = val_tuple
		#	if file_status == 'deleted':
		#		print(f'\t[-] {key}')
		#	else:
		#		print(f'\t[+] {key} [{file_type}, {file_size} bytes]')
		return fs_changes

	except Exception as e:
		raise Exception(f'error dumping filesystem changes: {str(e)}')

def commit_filesystem_changes(fs_changes):
	try:
		for item in fs_changes:
			src, dst, typ, status  = item
			if status == 'new':
				logging.debug(f'Creating new {typ}: {dst}')
			else:
				logging.debug(f'Copying modified {typ}: {dst}')

			# use copy2 to preserve metadata (e.g., timestamps)
			if typ == 'DIR':
				shutil.copytree(src, dst)
			else:
				shutil.copy2(src, dst)
	except Exception as e:
		# rollback
		logging.debug(f'error commiting filesystem changes: {str(e)}. Rolling back.')
		print(f'Error commiting filesystem changes. Rolling back.')
		for item in fs_changes:
			src, dst, typ, status  = item
			try:
				if status == 'new':
					if typ == 'DIR':
						shutil.rmtree(dst)
					else:
						os.remove(dst)
			except:
				pass

def clean_up(sandbox_root):
	try:
		shutil.rmtree(sandbox_root)
	except:
		pass

# install package under a sandbox
def run_sandbox(rules, install_cmd):

	# build profile and execute under sandbox
	try:
		logging.debug(f'Sandboxing installation {install_cmd}')

		# paths to libs/binaries
		cwd = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
		install_bin = os.path.join(cwd, 'install.sh')

		# validate paths
		strace_bin = os.path.join(cwd, 'strace')
		if not os.path.exists(strace_bin):
			raise Exception(f'{strace_bin} not found. Run {install_bin}')

		libstrace_path = os.path.join(cwd, 'libstrace.so')
		if not os.path.exists(libstrace_path):
			raise Exception(f'{libstrace_path} not found. Re-run {install_bin}')

		libsbox_path = os.path.join(cwd,'libsbox.so')
		if not os.path.exists(libsbox_path):
			raise Exception(f'{libsbox_path} not found. Re-run {install_bin}')

		os.environ['LD_LIBRARY_PATH'] = cwd
		os.environ['LD_PRELOAD'] = libsbox_path

		# validate that the binary works
		check_strace_cmd = [strace_bin, '--version']
		stdout, stderr, error = exec_command("check strace", check_strace_cmd, env=os.environ, redirect_mask=3)
		if error:
			logging.debug(f'{check_strace_cmd} failed:\n{stdout}\n{stderr}')
			raise Exception(f'{strace_bin} failed. Re-run {install_bin}')

		# temp log files
		sandbox_dir = tempfile.mkdtemp(prefix=f'packj_sandbox_')
		_, trace_filepath = tempfile.mkstemp(prefix='trace_', dir=sandbox_dir, suffix='.log')

		# sandboxing root and rules file
		sandbox_root = tempfile.mkdtemp(prefix=f'root_', dir=sandbox_dir)
		sandbox_logfile = sandbox_root + '.csv'

		_, rules_filepath = tempfile.mkstemp(prefix='rules_', dir=sandbox_dir, suffix='.profile')
		with open(rules_filepath, 'w+') as f:
			f.write(rules)

		os.environ['SANDBOX_ROOT'] = sandbox_root
		os.environ['SANDBOX_RULES'] = rules_filepath

		# execute command
		strace_cmd = f'{strace_bin} -fc --quiet=attach,personality -o {trace_filepath} {install_cmd}'
		stdout, stderr, error = exec_command("sandbox", strace_cmd.split(' '), env=os.environ, redirect_mask=0)
		if error or not os.path.exists(sandbox_logfile):
			if stderr:
				msg = stderr.replace('./strace: ','')
			elif error:
				msg = f'installation error ({error})'
			else:
				msg = f'log file {sandbox_logfile} does not exist'
			logging.debug(f'out:\n{msg}')
			raise Exception(msg)

		return sandbox_root, sandbox_logfile
	except Exception as e:
		print(f'Failed: {str(e)}!')
		return None, None

def dump_menu():
	print('')
	menu = '[C]ommit all changes, [Q|q]uit & discard changes, [L|l]ist details: '
	choice = None
	while choice not in ['C', 'Q', 'q', 'l', 'L']:
		choice = input(f'{menu}')
	return choice

def review_events(fs_events, fs_tree_root, net_events, details=False):
	try:
		while True:

			review_type = 'summarized' if not details else 'detailed'

			header = '\n#############################\n'
			header += f'# Review {review_type} activity'
			header += '\n#############################\n'

			print(header)
			dump_net_events(net_events, details=details)
			fs_changes = dump_fs_events(fs_events, fs_tree_root, details=details)

			choice = dump_menu()
			if choice.lower() == 'l':
				details = True
			elif choice.lower() == 'q':
				return fs_changes, False
			else:
				return fs_changes, True

	except Exception as e:
		print(f'Failed to dump parsed data (details: {details}): {str(e)}!')
		return None, False

def main(args):

	# only works on Linux
	if not sys.platform.startswith('linux'):
		print('Sandbox is only supported on Linux.')
		exit(0)

	install_cmd = ' '.join([args.pm_tool, 'install'] + args.install_args)

	# get sandboxing policies
	rules = build_sandboxing_profile(args.pm_tool)

	# execute command
	sandbox_root, sandbox_logfile = run_sandbox(rules, install_cmd)
	if not sandbox_root:
		exit(1)

	# parse events
	fs_events, fs_tree_root, net_events = parse_sandbox_log(sandbox_root, sandbox_logfile)

	# review activity
	fs_changes, commit = review_events(fs_events, fs_tree_root, net_events)

	# commit all changes -- actual installation
	if commit and fs_changes:
		commit_filesystem_changes(fs_changes)

	# clean up
	clean_up(sandbox_root)

############
# tests
############
def run_tests():
	import sys

	sandbox_root = sys.argv[1]
	assert os.path.exists(sandbox_root), f'{sandbox_root} does not exist'

	sandbox_logfile = sandbox_root + '.csv'
	assert os.path.exists(sandbox_logfile), f'{sandbox_logfile} does not exist'

	# parse events
	fs_events, fs_tree_root, net_events = parse_sandbox_log(sandbox_root, sandbox_logfile)

	# review 
	fs_changes, commit = review_events(fs_events, fs_tree_root, net_events)
	if commit and fs_changes:
		commit_filesystem_changes(fs_changes)

############
# main
############
if __name__ == "__main__":
	run_tests()
