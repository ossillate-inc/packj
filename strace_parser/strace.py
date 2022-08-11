#c!/usr/bin/python

#
# pystrace -- Python tools for parsing and analysing strace output files
#
#
# Copyright 2012
#      The President and Fellows of Harvard College.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of the University nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE UNIVERSITY AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE UNIVERSITY OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
#
# Contributor(s):
#   Peter Macko (http://eecs.harvard.edu/~pmacko)
#

import re
import sys
import _io

import strace_parser.strace_utils

from decimal import *


#
# Initialize regular expressions
#

global re_get_pid
re_get_pid \
        = re.compile(r"(\d+) .*")

global re_extract
re_extract \
        = re.compile(r"\s*(\d+\.\d+) (\w+)(\(.*) <(.+)>$")

global re_extract_no_elapsed
re_extract_no_elapsed \
        = re.compile(r"\s*(\d+\.\d+) (\w+)(\(.*)$")

global re_extract_unfinished
re_extract_unfinished \
        = re.compile(r"\s*(\d+\.\d+ .*) <unfinished \.\.\.>$")

global re_extract_resumed
re_extract_resumed \
        = re.compile(r"\s*(\d+\.\d+) <\.\.\. [\a-zA-Z\d]+ resumed>(.*)$")

global re_extract_signal
re_extract_signal \
        = re.compile(r"\s*(\d+\.\d+) --- (\w+) \{(.)*\} ---$")

global re_extract_exit
re_extract_exit \
        = re.compile(r"\s*(\d+\.\d+) \+\+\+ exited with (-?[\d]+) \+\+\+$")

global re_extract_kill
re_extract_kill \
        = re.compile(r"\s*(\d+\.\d+) \+\+\+ killed by ([\w]+) \+\+\+$")

global re_extract_arguments_and_return_value_none
re_extract_arguments_and_return_value_none \
        = re.compile(r"\((.*)\)[ \t]*= (\?)$")

global re_extract_arguments_and_return_value_ok
re_extract_arguments_and_return_value_ok \
        = re.compile(r"\((.*)\)[ \t]*= (-?\d+)$")

global re_extract_arguments_and_return_value_ok_hex
re_extract_arguments_and_return_value_ok_hex \
        = re.compile(r"\((.*)\)[ \t]*= (-?0[xX][a-fA-F\d]+)$")

global re_extract_arguments_and_return_value_error
re_extract_arguments_and_return_value_error \
        = re.compile(r"\((.*)\)[ \t]*= (-?\d+) (\w+) \([\w ]+\)$")

global re_extract_arguments_and_return_value_error_unknown
re_extract_arguments_and_return_value_error_unknown \
        = re.compile(r"\((.*)\)[ \t]*= (\?) (\w+) \([\w ]+\)$")

global re_extract_arguments_and_return_value_ext
re_extract_arguments_and_return_value_ext \
        = re.compile(r"\((.*)\)[ \t]*= (-?\d+) \(([^()]+)\)$")

global re_extract_arguments_and_return_value_ext_hex
re_extract_arguments_and_return_value_ext_hex \
        = re.compile(r"\((.*)\)[ \t]*= (-?0[xX][a-fA-F\d]+) \(([^()]+)\)$")


#
# A strace entry
#
class StraceEntry:
    '''
    A strace entry
    '''

    def __init__(self, pid, timestamp, was_unfinished, elapsed_time,
                 syscall_name, syscall_arguments, return_value):
        self.pid = pid
        self.timestamp = timestamp
        self.was_unfinished = was_unfinished
        self.elapsed_time = elapsed_time
        self.syscall_name = syscall_name
        self.syscall_arguments = syscall_arguments
        self.return_value = return_value
        self.category = self.__get_category()

    
    def __get_category(self):
        # Should mmap() be in this category?
        if self.syscall_name in ["read", "write", "open", "close", "lseek",
                "llseek", "__llseek", "stat", "stat64", "fstat", "chmod",
                "access", "rename", "mkdir", "getdents", "fcntl", "unlink",
                "fseek", "rewind", "ftell", "fgetpos", "fsetpos", "fclose",
                "fsync", "creat", "readdir", "opendir", "rewinddir", "scandir",
                "seekdir", "telldir", "flock", "lockf", "mmap"]:
            return "IO"
        else:
            return None


#
# An input stream
#
class StraceInputStream:
    '''
    A strace input stream
    '''

    
    def __init__(self, input):
        '''
        Initialize (open) the strace input stream from the given input (file
        object or file name)
        '''
        self.input = input
        #breakpoint()
        #if type(input) == file:
        if isinstance(input, _io.TextIOWrapper):
            self.f_in = input
        elif input == None:
            self.f_in = sys.stdin
        elif isinstance(input, str):
            self.f_in = open(input)
        else:
            raise Exception("Invalid type of argument \"input\"")
        self.line_no = 0
        self.have_pids = False
        self.unfinished_syscalls = dict()       # PID --> line


    def __iter__(self):
        '''
        Return an iterator
        '''
        return self


    def __parse_arguments(self, arguments_str, include_quotes=True,
            include_ellipsis=True):
        '''
        Parse the given argument string and return an array of substrings
        '''

        arguments = []
        current_arg = ""
        quote_type = None
        escaped = False
        expect_comma = False
        between_arguments = False
        nest_stack = []

        failed = False 

        for c in arguments_str:

            # Characters between arguments

            if between_arguments and c in [' ', '\t']:
                continue
            else:
                between_arguments = False
            if expect_comma:
                assert quote_type is None
                if c == '.':
                    if include_ellipsis:
                        current_arg += c
                elif c == ',':
                    expect_comma = False
                    between_arguments = True
                    arguments.append(current_arg)
                    current_arg = ""

                continue


            # Arguments

            if escaped:
                current_arg += c
                escaped = False
            elif c == '\\':
                current_arg += c
                escaped = True
            elif c in ['"', '\'', '[', ']', '{', '}']:
                if quote_type in ['"', '\''] and c != quote_type:
                    current_arg += c
                elif c == quote_type:
                    if include_quotes or len(nest_stack) > 0:
                        current_arg += c
                    if len(nest_stack) > 1:
                        nest_stack.pop()
                        quote_type = nest_stack[-1]
                    else:
                        nest_stack.pop()
                        quote_type = None
                        if not current_arg == '[?]':
                                expect_comma = True
                elif c in [']', '}']:
                    current_arg += c
                else:
                    if include_quotes or len(nest_stack) > 0:
                        current_arg += c
                    if c == '[': c = ']'
                    if c == '{': c = '}'
                    quote_type = c
                    nest_stack.append(c)
            elif c == ',' and quote_type is None:
                arguments.append(current_arg)
                current_arg = ""
                between_arguments = True
            else:
                current_arg += c

        #if failed:
            #return

        if quote_type is not None:
            raise Exception(("Expected '%s' but found end of the string; " \
                    + "offending string: %s") % (quote_type, arguments_str))

        if len(current_arg) > 0:
            arguments.append(current_arg)
        return arguments

    def next(self):
        return self.__next__()

    def __next__(self):
        '''
        Return the next complete entry. Raise StopIteration if done
        '''
        line = self.f_in.__next__()
        if line is None:
            raise StopIteration
            
        line = line.strip()
        self.line_no += 1
        pos_start = 0
        
        if line == "":
            if self.line_no == 1:
                raise Exception("The first line needs to be valid")
            else:
                return self.next()
        if not line[0].isdigit():
            if self.line_no == 1:
                raise Exception("The first line needs to be valid")
            else:
                return self.next()
        
        
        # Get the PID (if available)
        
        pid = None
        m_pid = re_get_pid.match(line)
        if self.line_no == 1:
            self.have_pids = m_pid is not None
        elif self.have_pids != (m_pid is not None):
            raise Exception("Inconsistent file - some lines have PIDs, "
                + "some don't (line %d)" % self.line_no)
        if m_pid is not None:
            pid = int(m_pid.group(1))
            pos_start = len(m_pid.group(1)) + 1
                
        
        # Signals
        
        if line.endswith("---"):
            r = re_extract_signal.match(line, pos_start)
            if r is not None:
                timestamp = Decimal(r.group(1))
                signal_name = r.group(2)
                arguments = self.__parse_arguments(r.group(3))
                return StraceEntry(pid, timestamp, False, 0, signal_name, arguments, 0)
        
        # Exit/Kill
        
        if line.endswith("+++"):
            r = re_extract_exit.match(line, pos_start)
            if r is not None:
                timestamp = Decimal(r.group(1))
                return_value = r.group(2)
                return StraceEntry(pid, timestamp, False, 0, "EXIT", [], return_value)

            r = re_extract_kill.match(line, pos_start)
            if r is not None:
                timestamp = Decimal(r.group(1))
                return StraceEntry(pid, timestamp, False, 0, "KILL", [r.group(2)], 0)
        
        
        # Unfinished and resumed syscalls
        
        if line.endswith("<unfinished ...>"):
            r = re_extract_unfinished.match(line, pos_start)
            if r is None:
                raise Exception("Invalid \"unfinished\" statement (line %d)"
                    % self.line_no)
            self.unfinished_syscalls[pid] = r.group(1)
            return self.next()
        
        r = re_extract_resumed.match(line, pos_start)
        if r is not None:
            was_unfinished = True
            if pid not in self.unfinished_syscalls.keys() \
                or self.unfinished_syscalls[pid] is None:
                raise Exception("No line to resume (line %d)" % self.line_no)
            line = self.unfinished_syscalls[pid] + r.group(2)
            self.unfinished_syscalls[pid] = None
            pos_start = 0
        else:
            was_unfinished = False
            
        
        # Extract basic information
        
        r = re_extract.match(line, pos_start)
        if r is not None:
            timestamp = Decimal(r.group(1))
            syscall_name = r.group(2)
            args_and_result_str = r.group(3)
            elapsed_time = r.group(4)
            if elapsed_time[0].isdigit():
                elapsed_time = Decimal(elapsed_time)
            elif elapsed_time == "unavailable":
                elapsed_time = None
            else:
                raise Exception("Invalid elapsed time (line %d)" % self.line_no)
        else:
            r = re_extract_no_elapsed.match(line, pos_start)
            if r is not None:
                timestamp = Decimal(r.group(1))
                syscall_name = r.group(2)
                args_and_result_str = r.group(3)
                elapsed_time = None
            else:
                #sys.stderr.write("Offending line: %s\n" % line)
                raise Exception("Invalid line (line %d)" % self.line_no)
        
        
        # Extract the return value
        
        m_args_and_result \
          = re_extract_arguments_and_return_value_ok.match(args_and_result_str)
        if m_args_and_result != None:
            return_value = int(m_args_and_result.group(2))
            arguments_str = m_args_and_result.group(1)
        if m_args_and_result == None:
            m_args_and_result \
              = re_extract_arguments_and_return_value_ok_hex.match(args_and_result_str)
            if m_args_and_result != None:
                return_value = m_args_and_result.group(2)
                arguments_str = m_args_and_result.group(1)
        if m_args_and_result == None:
            m_args_and_result \
              = re_extract_arguments_and_return_value_error.match(args_and_result_str)
            if m_args_and_result != None:
                return_value = m_args_and_result.group(2)
                arguments_str = m_args_and_result.group(1)
        if m_args_and_result == None:
            m_args_and_result \
              = re_extract_arguments_and_return_value_error_unknown.match(args_and_result_str)
            if m_args_and_result != None:
                return_value = m_args_and_result.group(2)
                arguments_str = m_args_and_result.group(1)
        if m_args_and_result == None:
            m_args_and_result \
              = re_extract_arguments_and_return_value_ext.match(args_and_result_str)
            if m_args_and_result != None:
                return_value = m_args_and_result.group(2)
                arguments_str = m_args_and_result.group(1)
        if m_args_and_result == None:
            m_args_and_result \
              = re_extract_arguments_and_return_value_ext_hex.match(args_and_result_str)
            if m_args_and_result != None:
                return_value = m_args_and_result.group(2)
                arguments_str = m_args_and_result.group(1)
        if m_args_and_result == None:
            m_args_and_result \
              = re_extract_arguments_and_return_value_none.match(args_and_result_str)
            if m_args_and_result != None:
                return_value = None
                arguments_str = m_args_and_result.group(1)
        if m_args_and_result == None:
                raise Exception("Invalid line (line %d)" % self.line_no)
        
        
        # Extract the arguments
        
        arguments = self.__parse_arguments(arguments_str)
        
        
        # Finish
        
        return StraceEntry(pid, timestamp, was_unfinished, elapsed_time,
                           syscall_name, arguments, return_value)
    
    
    def close(self):
        '''
        Close the input stream (unless it is sys.stdin)
        '''
        if self.f_in is not sys.stdin:
            self.f_in.close()
        self.f_in = None


#
# A process in a strace output
#
class StraceTracedProcess:
    '''
    A process in a strace output
    '''
    
    def __init__(self, pid, name):
        '''
        Initialize the traced process object
        '''
        self.pid = pid
        self.name = name
        self.entries = []


#
# The contents of a strace file
#
class StraceFile:
    '''
    A strace input stream
    '''

    
    def __init__(self, input):
        '''
        Load the strace file contents from the given input (file name, file
        object, or None for standard input)
        '''
        self.input = input
        self.have_pids = False
        self.content = []
        self.processes = dict()

        self.start_time = None
        self.last_timestamp = None
        self.finish_time = None
        self.elapsed_time = None


        # Process the file
        
        strace_stream = StraceInputStream(input)
        
        for entry in strace_stream:
            
            self.have_pids = strace_stream.have_pids
            if entry.pid not in self.processes.keys():
                self.processes[entry.pid] = StraceTracedProcess(entry.pid, None)
            if self.processes[entry.pid].name is None:
                if entry.syscall_name == "execve":
                    self.processes[entry.pid].name = \
                            strace_utils.array_safe_get(entry.syscall_arguments,0)

            self.processes[entry.pid].entries.append(entry)
            self.content.append(entry)


            # Analyze the timestamps

            if self.start_time is None:
                self.start_time = entry.timestamp
            if self.last_timestamp is None:
                self.last_timestamp = entry.timestamp
            if self.start_time > entry.timestamp:
                self.start_time = entry.timestamp
            if self.last_timestamp < entry.timestamp:
                self.last_timestamp = entry.timestamp
            
            entry_finish_time = entry.timestamp
            if entry.elapsed_time is not None:
                entry_finish_time += entry.elapsed_time
            if self.finish_time is None:
                self.finish_time = entry_finish_time
            if self.finish_time < entry_finish_time:
                self.finish_time = entry_finish_time
        
        if self.start_time is not None:
            self.elapsed_time = self.finish_time - self.start_time


        # Close

        if type(input) == file:
            strace_stream.close()
