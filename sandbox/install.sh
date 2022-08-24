echo -n "Setting up Packj sandbox tool...."
currdir=$(pwd)
if [ ! -f $currdir/install.sh ]; then
	echo "run this script from inside 'sandbox' dir."
	exit
else
	echo "may take up to 4 mins"
fi

echo -n "[+] Checking for strace executable..."
if [ -f ./strace ]; then
	echo "OK [exists]"
else
	echo "OK [not found]"

	# remove stale installation
	rm -rf /tmp/strace

	echo -n "	[+] Clonning strace..."
	git clone -q --depth 1 --branch v5.19 -c advice.detachedHead=false https://github.com/strace/strace /tmp/strace
	if [ $? -ne 0 ]; then
		echo "Failed"
		exit
	else
		echo "Done"
	fi

	cd /tmp/strace

	# Bootstrap
	echo -n "	[+] Unpacking strace (est: 2mins)..."
	./bootstrap &> /dev/null
	if [ $? -ne 0 ]; then
		rm -rf /tmp/strace
		echo "Failed"
		exit
	else
		echo "Done"
	fi

	# Configure
	echo -n "	[+] Configuring strace (est: 2mins)..."
	CFLAGS='-fPIC' ./configure --enable-mpers=no &> /dev/null
	if [ $? -ne 0 ]; then
		rm -rf /tmp/strace
		echo "Failed"
		exit
	else
		echo "Done"
	fi

	# Make
	echo -n "	[+] Compiling strace library..."
	make -j4 &> /dev/null
	if [ $? -ne 0 ]; then
		rm -rf /tmp/strace
		echo "Failed to build strace"
		exit
	else
		echo "Done"
	fi

	# Final executable
	echo -n "	[+] Creating strace executable..."
	cd src
	gcc -fPIC -shared -o libstrace.so strace.c -DHAVE_CONFIG_H -Ilinux/x86_64/ libstrace_a-*.o gen/libstrace_a-gen_hdio.o
	if [ $? -ne 0 ]; then
		rm -rf /tmp/strace
		echo "Failed"
	else
		cp libstrace.so $currdir/.
		gcc strace.c -o strace -DHAVE_CONFIG_H -Ilinux/x86_64/ -L/tmp/strace/src -lstrace -lrt
		if [ $? -ne 0 ]; then
			rm -rf libstrace* /tmp/strace
			echo "Failed"
			exit
		else
			cp strace $currdir/.
			echo "Done"
		fi
	fi
fi

echo -n "[+] Checking sandbox library..."
if [ ! -f $currdir/libsbox.so ]; then
	echo "Failed [not found!]"
	exit
else
	echo "OK [available]"
fi

echo "=================================="
echo "Setup ready! Run main.py located in the parent dir."
