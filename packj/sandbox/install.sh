#!/usr/bin/env bash

set -uo pipefail
IFS=$'\n\t'

echo -n "Setting up Packj sandbox tool...."

currdir=$(pwd)
logfile=/tmp/packj-strace.build.log
tmpdir=/tmp/packj-strace

if [ "$1" == "-v" ]; then
	verbose=true
else
	verbose=false
fi

run_command() {
    if [ $verbose = true ]; then
		$@ 2>&1
	else
		$@ >> $logfile 2>&1
	fi
}

log() {
	if [ $verbose = true ]; then
		echo $@
	else
		echo $@ >> $logfile
	fi
}

if [ ! -f $currdir/install.sh ]; then
	echo "run this script from inside 'sandbox' dir."
	exit 1
else
	echo "may take up to 5 mins"
fi

echo -n "[+] Checking for strace executable..."
if [ -f ./strace ]; then
	echo "OK [exists]"
else
	echo "OK [not found]"

	# remove stale installation
	rm -rf $tmpdir

	echo -n "	[+] Cloning strace..."
	run_command git clone --depth 1 --branch v5.19 -c advice.detachedHead=false https://github.com/strace/strace $tmpdir
	if [ $? -ne 0 ]; then
		echo "Failed"
		exit 1
	else
		echo "Done"
	fi

	cd $tmpdir
	log "==============================="

	# Bootstrap
	echo -n "	[+] Unpacking strace (est: 2mins)..."
    run_command "./bootstrap"
	if [ $? -ne 0 ]; then
		rm -rf $tmpdir
		echo "Failed"
		exit 1
	else
		echo "Done"
	fi

	log "==============================="

	# Configure
	echo -n "	[+] Configuring strace (est: 2mins)..."
	CFLAGS='-fPIC' run_command ./configure --enable-mpers=no --with-libselinux=no
	if [ $? -ne 0 ]; then
		rm -rf $tmpdir
		echo "Failed"
		exit 1
	else
		echo "Done"
	fi

	log "==============================="

	# Make
	echo -n "	[+] Compiling strace library..."
	run_command make -j4
	if [ $? -ne 0 ]; then
		rm -rf $tmpdir
		echo "Failed to build strace"
		exit 1
	else
		echo "Done"
	fi

	# Final executable
	echo -n "	[+] Creating strace executable..."
	cd $tmpdir/src
	run_command gcc -fPIC -shared -o libstrace.so strace.c -DHAVE_CONFIG_H -Ilinux/x86_64/ libstrace_a-*.o gen/libstrace_a-gen_hdio.o
	if [ $? -ne 0 ]; then
		rm -rf $tmpdir
		echo "Failed"
		exit 1
	else
		cp libstrace.so $currdir/.
		run_command gcc strace.c -o strace -DHAVE_CONFIG_H -Ilinux/x86_64/ -L$tmpdir/src -lstrace -lrt
		if [ $? -ne 0 ]; then
			rm -rf libstrace* $tmpdir
			echo "Failed"
			exit 1
		else
			cp strace $currdir/.
			echo "Done"
		fi
	fi
fi

log "==============================="

echo -n "[+] Compiling sandbox library..."
if [ ! -f $currdir/libsbox.so ]; then
	cd $currdir
	LIBSTRACE_PATH=. run_command make
	if [ $? -ne 0 ]; then
		rm -rf $tmpdir
		echo "Failed"
		exit 1
	else
		echo "Done"
	fi
else
	echo "OK [available]"
fi

echo "=================================="
echo "Setup ready! Run main.py located in the parent dir."
