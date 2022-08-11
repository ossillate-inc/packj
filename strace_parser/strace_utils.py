#!/usr/bin/python

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


#
# Safe get from an array -- return None if index out of range
#
def array_safe_get(array, index):
	'''
	Safe get from an array -- return None if index out of range
	'''

	if index >= 0 and index < len(array):
		return array[index]
	else:
		return ""


#
# Escape a string for a .csv
#
def csv_escape(s, quote='"'):
	'''
	Escape a string for a .csv
	'''
	r = ""
	if s is None: return ""
	if s == "": return ""
	if type(s) == int: return str(s)
	if type(s) == float: return "%0.6f" % s
	for c in str(s):
		if c == quote: r += quote
		r += c
	return quote + r + quote


#
# Write a line to a .cvs file
#
def csv_write_row(file_stream, *arguments):
	'''
	Write a line to a .csv file
	'''
	csv_write_row_array(file_stream, arguments)


#
# Write a line to a .cvs file
#
def csv_write_row_array(file_stream, arguments, separator=',', quote='"'):
	'''
	Write a line to a .csv file
	'''
	s = ""
	for a in arguments:
		if s != "": s += separator
		s += csv_escape(a, quote)
	file_stream.write(s)
	file_stream.write("\n")
