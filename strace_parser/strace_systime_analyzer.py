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

import getopt
import math
import os.path
import sys

import strace
import strace_utils


#
# Analyze the systime
#
def analyze_systime(input_file, output_file=None, bin_size=0.1, \
		separator=',', quote='"'):
	'''
	Analyze the systime
	
	Arguments:
	  input_file  - the input file, or None for standard input
	  output_file - the output file, or None for standard output
	  bin_size    - the size of a bin
	'''

	# Open the files
	
	if input_file is not None:
		f_in = open(input_file, "r")
	else:
		f_in = sys.stdin
	
	if output_file is not None:
		f_out = open(output_file, "w")
	else:
		f_out = sys.stdout
	
	
	# Read in the file
	
	strace_file = strace.StraceFile(f_in)
	if len(strace_file.processes) == 0:
		if f_out is not sys.stdout: f_out.close()
		return


	# Process the file

	num_bins = int(math.ceil((strace_file.elapsed_time) / bin_size))
	bins_per_process = dict()

	for e in strace_file.content:
		if e.pid not in bins_per_process.keys():
			bins = [0] * num_bins
			bins_per_process[e.pid] = bins
		else:
			bins = bins_per_process[e.pid]

		t_start = e.timestamp - strace_file.start_time
		t_end = t_start
		if e.elapsed_time is not None: t_end += e.elapsed_time
		bin_start = int(math.floor(t_start / bin_size))
		bin_end = int(math.ceil(t_end / bin_size))  # exclusive

		for i in xrange(bin_start, bin_end):
			bin_t_start = i * bin_size
			bin_t_end   = bin_t_start + bin_size
			b = bin_size
			if t_start > bin_t_start: b -= t_start - bin_t_start
			if t_end   < bin_t_end  : b -= bin_t_end - t_end
			bins[i] += b
	

	# Print the result

	pids = strace_file.processes.keys()
	
	header = ["TIME"]
	for p in pids:
		header.append("[%d] %s" % (p, strace_file.processes[p].name))
	strace_utils.csv_write_row_array(f_out, header)

	for i in xrange(0, num_bins):
		data = [i * bin_size]
		for p in pids:
			data.append(bins_per_process[p][i] / bin_size)
		strace_utils.csv_write_row_array(f_out, data)


	# Close the files

	if f_out is not sys.stdout:
		f_out.close()


#
# Print the usage information
#
def usage():
	sys.stderr.write('Usage: %s [OPTIONS] [FILE]\n\n'
		% os.path.basename(sys.argv[0]))
	sys.stderr.write('Options:\n')
	sys.stderr.write('  -h, --help         Print this help message and exit\n')
	sys.stderr.write('  -o, --output FILE  Print to file instead of the standard output\n')


#
# The main function
#
# Arguments:
#   argv - the list of command-line arguments, excluding the executable name
#
def main(argv):

	input_file = None
	output_file = None
	

	# Parse the command-line options

	try:
		options, remainder = getopt.gnu_getopt(argv, 'ho:',
			['help', 'output='])
		
		for opt, arg in options:
			if opt in ('-h', '--help'):
				usage()
				return
			elif opt in ('-o', '--output'):
				output_file = arg
		
		if len(remainder) > 1:
			raise Exception("Too many options")
		elif len(remainder) == 1:
			input_file = remainder[0]
	except Exception as e:
		sys.stderr.write("%s: %s\n" % (os.path.basename(sys.argv[0]), e))
		sys.exit(1)
	
	
	# Process the file

	try:
		analyze_systime(input_file, output_file)
	except IOError as e:
		sys.stderr.write("%s: %s\n" % (os.path.basename(sys.argv[0]), e))
		sys.exit(1)


#
# Entry point to the application
#
if __name__ == "__main__":
	main(sys.argv[1:])
