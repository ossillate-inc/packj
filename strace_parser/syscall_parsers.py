#!/usr/bin/python

import sys
import os
import re
import yaml
import site
import html

from dns import resolver, reversename

rules = None
with open('strace_parser/rules.yaml') as f:
    rules = yaml.safe_load(f)

ignore_read = { path for path in rules['ignore_read'] }
ignore_paths = { path for path in rules['ignore_paths'] }

for p in sys.path:
    if p != os.getcwd():
        ignore_read.add(p)
        ignore_paths.add(p)

ignore_read.add(site.USER_BASE)
ignore_paths.add(site.USER_SITE)

files_read = set()
files_created = set()
files_written = set()
ip_address_found = set()
process_found = set()
directories_created = set()
directories_removed = set()
file_unlinked = set()

OPENED_PATHS = {}
LAST_CHDIR_PATH = None

def unescape_path(path):
    return html.unescape(path).replace('"', '')

def check_paths(args_str, mode='read'):
    ignore_set = None

    if mode == 'all':
        ignore_set = ignore_paths
    elif mode == 'read':
        ignore_set = ignore_read

    for path in ignore_set:
        if path in args_str:
            return None

    return True

def collect_ips():
    domains = [ 'pypi.org', 'npmjs.org', 'rubygems.org' ]

    ip_data = {}

    for domain in domains:
        ips = {}

        results = resolver.query(domain, 'A')

        for result in results:
            ip = result.to_text()

            if ip not in ip_data:
                ip_data[ip] = domain

    return ip_data

ip_data = collect_ips()

def parse_chdir(ts, name, args_str, args, return_value):
    global LAST_CHDIR_PATH

    if return_value == 0:
        LAST_CHDIR_PATH = unescape_path(args_str)

def parse_void(ts, name, args_str, args, return_value):
    try:
        if return_value < 0:
            return
    except:
        return

    OPENED_PATHS[str(return_value)] = "dummy"

def parse_close(ts, name, args_str, args, return_value):
    key = str(args[0])
    try:
        d = OPENED_PATHS.pop(key)
    except KeyError:
        print(f"{ts}: key delete didn't go through for {key}")
    return
    
def parse_open(ts, name, args_str, args, return_value):

    if return_value < 0:
        return

    if "AT_FDCWD" == args[0]:
        path = unescape_path(args[1])
        if path[0] != '/' and LAST_CHDIR_PATH != None:
            path = LAST_CHDIR_PATH + path

        OPENED_PATHS[str(return_value)] = path

    if 'AT_FDCWD' not in args[0]:
        new_path = OPENED_PATHS[str(args[0])] + '/' + args[1]
        new_path = new_path.replace('"', '')

        path = unescape_path(new_path)
        if path[0] != '/' and LAST_CHDIR_PATH != None:
            path = LAST_CHDIR_PATH + path

        OPENED_PATHS[str(return_value)] = path

    if "O_RDONLY" in args_str and "O_DIRECTORY" in args_str:
        return None

    if not check_paths(args_str, 'all') or not check_paths(args_str, 'read'):
        return

    data = {}
    if 'O_RDONLY' in args_str:

        data['msg'] = "File read"

        updated_path = unescape_path(args[1])

        if 'AT_FDCWD' not in args[0]:
            path = OPENED_PATHS[str(return_value)]

            if not check_paths(path, 'read'):
                return

            if path in files_read: 
                return

            files_read.add(path)
            data['path'] = OPENED_PATHS[str(return_value)]

        else:
            if updated_path[0] != '/' and LAST_CHDIR_PATH != None:
                updated_path = LAST_CHDIR_PATH + updated_path

            if not check_paths(updated_path, 'read'):
                return

            if updated_path in files_read: 
                return

            files_read.add(updated_path)
            data['path'] = updated_path

    if 'node_modules' in args_str:
        return None

    if 'O_CREAT' in args_str:

        if args[0] in files_created:
            return None


        if args[0] == 'AT_FDCWD':
            return None

        files_created.add(args[0])

        data['msg'] = "File created"
        data['path'] = args[0]

    elif 'O_WRITE' in args_str or 'O_RDWR' in args_str:

        if args[0] in files_written:
            return None

        files_written.add(args[0])

        data['msg'] = "File written"
        data['path'] = args[0]

    return data

def parse_rename(ts, name, args_str, args, return_value):

    if not check_paths(args_str, mode='all'):
        return

    oldpath, newpath = args[0], args[1]

    data = {}
    data['oldpath'] = oldpath
    data['newpath'] = newpath
    data['msg'] = f"File path changed"
    return data

def parse_chmod(ts, name, args_str, args, return_value):
    if not check_paths(args_str, mode='all'):
        return

    data = {}

    path = unescape_path(args[0])
    if path[0] != '/' and LAST_CHDIR_PATH != None:
        path = LAST_CHDIR_PATH + path

    if not check_paths(path,'all'):
        return

    data['path'] = path

    if '1' in args[1] or '5' in args[1] or '7' in args[1]:
        data['msg'] = f"Alert: Executable found, permissions: {args[1]}"
    else:
        data['msg'] = f"permissions changed to {args[1]}"

    return data

def parse_create(ts, name, args_str, args, return_value):
    return parse_open(ts, name, args_str + ",O_CREAT", args)

def parse_execve(ts, name, args_str, args, return_value):
    path = args[0]
    if path in process_found:
        return None

    if return_value == 0:
        status = f"successful"
    else:
        status = f"failed!"
    process_found.add(path)
    data = {}
    data['program'] = path

    if '/rm' in path:
        deleted_dir = args[1].split('[')[1].split(']')[0].split(',')[2]
        deleted_dir = deleted_dir.lstrip()
        data['msg'] = f"directory removed: {deleted_dir}"
    else:
        data['msg'] = f"Program execution {status}"

    return data

def parse_clone(ts, name, args_str, args, return_value):
    return {
        'msg' : f'New process created with {name}'
    }

def parse_bind(ts, name, args_str, args, return_value):
    if 'AF_INET6' in args_str or 'AF_UNSPEC' in args_str:
        return None
    return {
        'msg' : f'Bind: {args[1]}',
    }

def parse_connect(ts, name, args_str, args, return_value):
    if 'AF_INET6' in args_str or 'AF_UNSPEC' in args_str:
        return None

    data = {
        'msg' : 'Connection attempted'
    }

    if "inet_addr" in args_str:
        o = re.search("\d+\.\d+\.\d+\.\d+", args_str)
        ip_address = o.group(0)

        if ip_address in ip_address_found:
            return None

        if ip_address in ip_data:
            data['domain'] = ip_data[ip_address]

        ip_address_found.add(ip_address)

        data['ip_address'] = ip_address

    data['info'] = args[1]
    return data

def parse_data_transfer(ts, name, args_str, args, return_value):

    ip_address = None
    data = {}

    if "inet_addr" in args_str:
        o = re.search("\d+\.\d+\.\d+\.\d+", args_str)
        ip_address = o.group(0)

        if ip_address:
            data['ip_address'] = ip_address

    msg = None

    if name == 'sendto':
        msg = 'Data sent'
    elif name == 'recvmsg':
        msg = 'Received sent'

    data['msg'] = msg
    data['data'] = args[1]
    return data

def parse_dir(ts, name, args_str, args, return_value):
    msg = None


    path = unescape_path(args[0])
    if path[0] != '/' and LAST_CHDIR_PATH != None:
        path = LAST_CHDIR_PATH + path

    if not check_paths(path, 'all'):
        return

    if name == 'mkdir':
        if path in directories_created:
            return
        
        directories_created.add(path)
        msg = 'Directory created'
    elif name == 'rmdir':
        if path in directories_removed:
            return
        
        directories_removed.add(path)
        msg = 'Directory removed'
    elif name == 'unlink':
        if path in file_unlinked:
            return
        
        file_unlinked.add(path)
        msg = 'File unlinked'

    return {
            'msg' : msg,
            'path': path
            }

def parse_unlinkat(ts, name, args_str, args, return_value):
    try:
        unlink_path = OPENED_PATHS[str(args[0])] + '/' + args[1]
        unlink_path = unlink_path.replace('"', '')
        if unlink_path[0] != '/' and LAST_CHDIR_PATH != None:
           unlink_path = LAST_CHDIR_PATH + unlink_path

        if not check_paths(unlink_path, 'all'):
            return
    except:
        print(f"unlink failed for {args_str}") 
        return

    return {
            'msg' : 'File unlinked',
            'path': unlink_path
            }

def parse_link(ts, name, args_str, args, return_value):
    try:
        return {
            'oldpath': args[0],
            'newpath': args[1],
            'msg': 'Hard link created'
        }
    except:
        print(f"Could not process link {args_str}")
        return
    
def parse_default(ts, name, args_str, args, return_value):
    return {'msg' : f'{name} not handled'}

