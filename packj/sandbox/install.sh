echo -n "Setting up Packj sandbox tool...."

currdir=$(pwd)
logfile=/tmp/strace.build.log
tmpdir=/tmp/strace

if [ ! -f $currdir/install.sh ]; then
	echo "run this script from inside 'sandbox' dir."
	exit
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

	echo -n "	[+] Clonning strace..."
	git clone -q --depth 1 --branch v5.19 -c advice.detachedHead=false https://github.com/strace/strace $tmpdir
	if [ $? -ne 0 ]; then
		echo "Failed"
		exit
	else
		echo "Done"
	fi

	cd $tmpdir
	echo "===============================" >> $logfile

	# Bootstrap
	echo -n "	[+] Unpacking strace (est: 2mins)..."
	./bootstrap > $logfile 2>&1
	if [ $? -ne 0 ]; then
		rm -rf $tmpdir
		echo "Failed [log: $logfile]"
		exit
	else
		echo "Done"
	fi

	echo "===============================" >> $logfile

	# Configure
	echo -n "	[+] Configuring strace (est: 2mins)..."
	CFLAGS='-fPIC' ./configure --enable-mpers=no --with-libselinux=no >> $logfile 2>&1
	if [ $? -ne 0 ]; then
		rm -rf $tmpdir
		echo "Failed"
		exit
	else
		echo "Done"
	fi

	echo "===============================" >> $logfile

	# Make
	echo -n "	[+] Compiling strace library..."
	make -j4 >> $logfile 2>&1
	if [ $? -ne 0 ]; then
		rm -rf $tmpdir
		echo "Failed to build strace"
		exit
	else
		echo "Done"
	fi

	# Final executable
	echo -n "	[+] Creating strace executable..."
	cd $tmpdir/src
	gcc -fPIC -shared -o libstrace.so strace.c -DHAVE_CONFIG_H -Ilinux/x86_64/ libstrace_a-*.o gen/libstrace_a-gen_hdio.o
	if [ $? -ne 0 ]; then
		rm -rf $tmpdir
		echo "Failed"
	else
		cp libstrace.so $currdir/.
		gcc strace.c -o strace -DHAVE_CONFIG_H -Ilinux/x86_64/ -L$tmpdir/src -lstrace -lrt
		if [ $? -ne 0 ]; then
			rm -rf libstrace* $tmpdir
			echo "Failed"
			exit
		else
			cp strace $currdir/.
			echo "Done"
		fi
	fi
fi

echo "===============================" >> $logfile

echo -n "[+] Compiling sandbox library..."
if [ ! -f $currdir/libsbox.so ]; then
	cd $currdir
	LIBSTRACE_PATH=. make >> $logfile 2>&1
	if [ $? -ne 0 ]; then
		rm -rf $tmpdir
		echo "Failed"
	else
		echo "Done"
	fi
else
	echo "OK [available]"
fi

echo "=================================="
echo "Setup ready! Run main.py located in the parent dir."
