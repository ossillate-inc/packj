# Linux system calls.
# http://man7.org/linux/man-pages/man2/syscalls.2.html
# Linux system calls categorized by linasm
# http://linasm.sourceforge.net/docs/syscalls/index.php
# Linux system calls, for 32-bit and 64-bit
# https://www.cs.utexas.edu/~bismith/test/syscalls/syscalls.html
# Generate JSON system call table from Linux source
# https://syscalls.kernelgrok.com/

from audit.strace_parser.syscall_parsers import *

syscall_table = {
	#
    # File operations
	#
	"CLOSE"		: { "parser" : parse_close,	"category"	: "files" },
	"CREAT"		: { "parser" : parse_create,	"category"	: "files" },
	"OPEN"		: { "parser" : parse_open,		"category"	: "files" },
	"OPENAT"	: { "parser" : parse_open,		"category"	: "files" },		
	"MKNOD"		: { "parser" : parse_default,	"category"	: "files" },
	"MKNODAT"	: { "parser" : parse_default,	"category"	: "files" },
	"RENAME"	: { "parser" : parse_rename,	"category"	: "files" },
	"RENAMEAT"	: { "parser" : parse_rename,	"category"	: "files" },
	"TRUNCATE"	: { "parser" : parse_default,	"category"	: "files" },
	"FTRUNCATE"	: { "parser" : parse_default,	"category"	: "files" },
	#"FALLOCATE"	: { "parser" : parse_default,	"category"	: "files" },

	#
    # Directory operations
	#
	"MKDIR"		: { "parser" : parse_dir,	"category"	: "files" },
	"MKDIRAT"	: { "parser" : parse_default,	"category"	: "files" },
	"RMDIR"		: { "parser" : parse_dir,	"category"	: "files" },
	#"GETCWD"	: { "parser" : parse_default,	"category"	: "files" },
	"CHDIR"	: { "parser" : parse_chdir,	"category"	: "files" },
	#"FCHDIR"	: { "parser" : parse_default,	"category"	: "files" },
	"CHROOT"	: { "parser" : parse_default,	"category"	: "files" },
	#"GETDENTS"			: { "parser" : parse_default,	"category"	: "files" },
	#"GETDENTS64"		: { "parser" : parse_default,	"category"	: "files" },
	#"LOOKUP_DCOOKIE"	: { "parser" : parse_default,	"category"	: "files" },

	#
    # Link operations
	#
	"LINK"		: { "parser" : parse_link,	"category"	: "files" },
	"SYMLINK"	: { "parser" : parse_default,	"category"	: "files" },
	"SYMLINKAT"	: { "parser" : parse_default,	"category"	: "files" },
	"UNLINK"	: { "parser" : parse_dir,	"category"	: "files" },
	"UNLINKAT"	: { "parser" : parse_unlinkat,	"category"	: "files" },
	#"READLINK"		: { "parser" : parse_default,	"category"	: "files" },
	#"READLINKAT"	: { "parser" : parse_default,	"category"	: "files" },

	#
    # Basic file attributes
	#
    #"UMASK",
	#"STAT",
	#"LSTAT",
	#"FSTAT",
	#"FSTATAT",
	"CHMOD"		: { "parser" : parse_chmod,		"category"	: "files" },
	"FCHMOD"	: { "parser" : parse_chmod,		"category"	: "files" },
	"FCHMODAT"	: { "parser" : parse_chmod,		"category"	: "files" },
	"CHOWN"		: { "parser" : parse_default,	"category"	: "files" },
	"LCHOWN"	: { "parser" : parse_default,	"category"	: "files" },
	"FCHOWN"	: { "parser" : parse_default,	"category"	: "files" },
	"FCHOWNAT"	: { "parser" : parse_default,	"category"	: "files" },
	#"UTIME",
	#"UTIMES",
	#"FUTIMESAT",
	#"UTIMENSAT",
	#"ACCESS",
	#"FACCESSAT",

	#
    # Extended file attributes
	#
	"SETXATTR"		: { "parser" : parse_default,	"category"	: "files" },
	"LSETXATTR"		: { "parser" : parse_default,	"category"	: "files" },
	"FSETXATTR"		: { "parser" : parse_default,	"category"	: "files" },
	#"GETXATTR"		: { "parser" : parse_default,	"category"	: "files" },
	#"LGETXATTR"	: { "parser" : parse_default,	"category"	: "files" },
	#"FGETXATTR",
	#"LISTXATTR",
	#"LLISTXATTR",
	#"FLISTXATTR",
	"REMOVEXATTR"		: { "parser" : parse_default,	"category"	: "files" },
	"LREMOVEXATTR"		: { "parser" : parse_default,	"category"	: "files" },
	"FREMOVEXATTR"		: { "parser" : parse_default,	"category"	: "files" },

	#
    # File descriptor manipulations
	#
	#"IOCTL"	: { "parser" : parse_default,	"category"	: "files" },
	"FCNTL"		: { "parser" : parse_void,	"category"	: "files" },
	"DUP"		: { "parser" : parse_void,	"category"	: "files" },
	"DUP2"		: { "parser" : parse_void,	"category"	: "files" },
	#"DUP3"		: { "parser" : parse_default,	"category"	: "files" },
	#"FLOCK"	: { "parser" : parse_default,	"category"	: "files" },

	#
    # Read/Write
	#
	#"READ"		: { "parser" : parse_default,	"category"	: "files" },
	#"READV"	: { "parser" : parse_default,	"category"	: "files" },
	#"PREAD"	: { "parser" : parse_default,	"category"	: "files" },
	#"PREADV"	: { "parser" : parse_default,	"category"	: "files" },
	#"WRITE"	: { "parser" : parse_default,	"category"	: "files" },
	#"WRITEV"	: { "parser" : parse_default,	"category"	: "files" },
	#"PWRITE"	: { "parser" : parse_default,	"category"	: "files" },
	#"PWRITEV"	: { "parser" : parse_default,	"category"	: "files" },
	#"LSEEK"	: { "parser" : parse_default,	"category"	: "files" },
	#"SENDFILE",

	#
    # Synchronized I/O
	#
    #"FDATASYNC",
	#"FSYNC",
	#"MSYNC",
	#"SYNC_FILE_RANGE",
	#"SYNC",
	#"SYNCFS",

	#
    # Asynchronous I/O
	#
    #"IO_SETUP",
	#"IO_DESTROY",
	#"IO_SUBMIT",
	#"IO_CANCEL",
	#"IO_GETEVENTS",

	#
    # Multiplexed I/O
	#
    #"SELECT",
	#"PSELECT6",
	#"POLL",
	#"PPOLL",
	#"EPOLL_CREATE",
	#"EPOLL_CREATE1",
	#"EPOLL_CTL",
	#"EPOLL_WAIT",
	#"EPOLL_PWAIT",

	#
    # Monitoring file events
	#
    #"INOTIFY_INIT",
	#"INOTIFY_INIT1",
	#"INOTIFY_ADD_WATCH",
	#"INOTIFY_RM_WATCH",
	#"FANOTIFY_INIT",
	#"FANOTIFY_MARK",

    # Miscellaneous
    #"FADVISE64",
	#"READAHEAD",
	#"GETRANDOM",

	#
    # Manually added
	#
    #"_LLSEEK",
	#"STAT64",
	#"READDIR",
	#"FSTATFS64",
	"TRUNCATE64"	: { "parser" : parse_default,	"category"	: "files" },
	"SENDFILE64"	: { "parser" : parse_default,	"category"	: "files" },
	#"FSTATFS",
	#"STATFS64",
	#"CREATE_MODULE",
	#"STATFS",
	#"FSTATAT64",
	#"FADVISE64_64",
	#"LSTAT64",
	#"FSTAT64",
	#"STATX",
    #"PREADV2",
	#"PWRITEV2",
	#"PREAD64",
	#"PWRITE64"
	"RENAMEAT2"		: { "parser" : parse_default,	"category"	: "files" },
	"FTRUNCATE64"	: { "parser" : parse_default,	"category"	: "files" },
	"LCHOWN32"		: { "parser" : parse_default,	"category"	: "files" },
	"CHOWN32"		: { "parser" : parse_default,	"category"	: "files" },
	"FCHOWN32"		: { "parser" : parse_default,	"category"	: "files" },
	#"FCNTL64"		: { "parser" : parse_default,	"category"	: "files" },
	#"SYNC_FILE_RANGE2",

	#
    # Socket operations
	#
	#"SOCKETPAIR",
	#"SETSOCKOPT",
	#"GETSOCKOPT",
	#"GETSOCKNAME",
	#"GETPEERNAME",
	"SOCKET"		: { "parser" : parse_void,		"category"	: "network" },
	"BIND"			: { "parser" : parse_bind,		"category"	: "network" },
	"LISTEN"		: { "parser" : parse_default,	"category"	: "network" },
	#"ACCEPT",
	#"ACCEPT4",
	"CONNECT"	: { "parser" : parse_connect,	"category"	: "network" },
	"LISTEN"	: { "parser" : parse_default,	"category"	: "network" },
	"SHUTDOWN"	: { "parser" : parse_default,	"category"	: "network" },

	#
    # Send/Receive
	#
	"RECVFROM"	: { "parser" : parse_data_transfer,	"category"	: "network" },
	#"RECVMSG"	: { "parser" : parse_default,	"category"	: "network" },
	#"RECVMMSG"	: { "parser" : parse_default,	"category"	: "network" },
	"SENDTO"	: { "parser" : parse_data_transfer,	"category"	: "network" },
	#"SENDMSG"	: { "parser" : parse_default,	"category"	: "network" },
	#"SENDMMSG"	: { "parser" : parse_default,	"category"	: "network" },

	#
    # Naming
	#
	"SETHOSTNAME"	: { "parser" : parse_default,	"category"	: "network" },
	"SETDOMAINNAME"	: { "parser" : parse_default,	"category"	: "network" },

	#
    # Packet filtering
	#
    #"BPF",

	#
    # Manually added
	#
    #"CLOSE",
	#"SOCKETCALL",
	"RECV"	: { "parser" : parse_default,	"category"	: "network" },
	"SEND"	: { "parser" : parse_default,	"category"	: "network" },

	#
    # Process creation and termination
	#
    #"CLONE",
	#"FORK",
	#"VFORK",
	"EXECVE"	: { "parser" : parse_execve,	"category"	: "process" },
	"EXECVEAT"	: { "parser" : parse_execve,	"category"	: "process" },
	#"EXIT",
	#"EXIT_GROUP",
	#"WAIT4",
	#"WAITID",

	#
    # Process id
	#
    #"GETPID",
	#"GETPPID",
	#"GETTID",

	#
    # Session id
	#
    #"SETSID",
	#"GETSID",

	#
    # Process group id
	#
    #"SETPGID",
	#"GETPGID",
	#"GETPGRP",

	#
    # Users and groups
	#
	"SETUID"	: { "parser" : parse_default,	"category"	: "process" },
	#"GETUID",
	"SETGID"	: { "parser" : parse_default,	"category"	: "process" },
	#"GETGID",
	"SETRESUID"	: { "parser" : parse_default,	"category"	: "process" },
	#"GETRESUID",
	"SETRESGID"	: { "parser" : parse_default,	"category"	: "process" },
	#"GETRESGID",
	"SETREUID"	: { "parser" : parse_default,	"category"	: "process" },
	"SETREGID"	: { "parser" : parse_default,	"category"	: "process" },
	"SETFSUID"	: { "parser" : parse_default,	"category"	: "process" },
	"SETFSGID"	: { "parser" : parse_default,	"category"	: "process" },
	#"GETEUID",
	#"GETEGID",
	#"SETGROUPS",
	#"GETGROUPS",

	#
    # Namespaces
	#
    #"SETNS",

	#
    # Resource limits
	#
	"SETRLIMIT"	: { "parser" : parse_default,	"category"	: "process" },
	#"GETRLIMIT",
	"PRLIMIT"	: { "parser" : parse_default,	"category"	: "process" },
	#"GETRUSAGE",
}


PROCESS_SYSCALLS = {
    # Process scheduling
    "SCHED_SETATTR",
	"SCHED_GETATTR",
	"SCHED_SETSCHEDULER",
	"SCHED_GETSCHEDULER",
	"SCHED_SETPARAM",
	"SCHED_GETPARAM",
	"SCHED_SETAFFINITY",
	"SCHED_GETAFFINITY",
	"SCHED_GET_PRIORITY_MAX",
	"SCHED_GET_PRIORITY_MIN",
	"SCHED_RR_GET_INTERVAL",
	"SCHED_YIELD",
	"SETPRIORITY",
	"GETPRIORITY",
	"IOPRIO_SET",
	"IOPRIO_GET",

    # Virtual memory
    "BRK",
	"MMAP",
	"MUNMAP",
	"MREMAP",
	"MPROTECT",
	"MADVISE",
	"MLOCK",
	"MLOCK2",
	"MLOCKALL",
	"MUNLOCK",
	"MUNLOCKALL",
	"MINCORE",
	"MEMBARRIER",
	"MODIFY_LDT",

    # Threads
    "CAPSET",
	"CAPGET",
	"SET_THREAD_AREA",
	"GET_THREAD_AREA",
	"SET_TID_ADDRESS",
	"ARCH_PRCTL",

    # Miscellaneous
    "USELIB",
	"PRCTL",
	"SECCOMP",
	"PTRACE",
	"PROCESS_VM_READV",
	"PROCESS_VM_WRITEV",
	"KCMP",
	"UNSHARE",

    # Manually added
    "GETUID32",
	"SETUID32",
	"GETEGID32",
	"SETRESUID32",
	"PRLIMIT64",
	"SETREUID32",
	"MMAP2",
	"GETEUID32",
	"SETFSGID32",
    "GETGROUPS32",
	"SETGROUPS32",
	"GETRESUID32",
	"GETRESGID32",
	"GETGID32",
	"SETGID32",
	"SETRESGID32",
	"SETFSUID32",
    "SETREGID32",
	"NICE",
}

TIME_SYSCALLS = {
	#
    # Current time of day
	#
    "TIME",
	"SETTIMEOFDAY",
	"GETTIMEOFDAY",

	#
    # POSIX clocks
	#
    "CLOCK_SETTIME",
	"CLOCK_GETTIME",
	"CLOCK_GETRES",
	"CLOCK_ADJTIME",
	"CLOCK_NANOSLEEP",

	#
    # Clocks-based timers
	#
    "TIMER_CREATE",
	"TIMER_DELETE",
	"TIMER_SETTIME",
	"TIMER_GETTIME",
	"TIMER_GETOVERRUN",

	#
    # Timers
	#
    "ALARM",
	"SETITIMER",
	"GETITIMER",

	#
    # File descriptor based timers
	#
    "TIMERFD_CREATE",
	"TIMERFD_SETTIME",
	"TIMERFD_GETTIME",

	#
    # Miscellaneous
	#
    "ADJTIMEX",
	"NANOSLEEP",
	"TIMES"
}

SIGNAL_SYSCALLS = {
	#
    # Standard signals
	#
    "KILL",
	"TKILL",
	"TGKILL",
	"PAUSE",

	#
    # Real-time signals
	#
    "RT_SIGACTION",
	"RT_SIGPROCMASK",
	"RT_SIGPENDING",
	"RT_SIGQUEUEINFO",
	"RT_TGSIGQUEUEINFO",
	"RT_SIGTIMEDWAIT",
	"RT_SIGSUSPEND",
	"RT_SIGRETURN",
	"SIGALTSTACK",

	#
    # File descriptor based signals
	#
    "SIGNALFD",
	"SIGNALFD4",
	"EVENTFD",
	"EVENTFD2",

	#
    # Miscellaneous
	#
    "RESTART_SYSCALL",
	"SIGACTION",'SIGNAL','SIGPENDING','SIGPROCMASK','SIGRETURN','SIGSUSPEND'
}

IPC_SYSCALLS = {
    # IPC
    "IPC",
    # Pipe
    "PIPE",
	"PIPE2",
	"TEE",
	"SPLICE",
	"VMSPLICE",
    # Shared memory
    "SHMGET",
	"SHMCTL",
	"SHMAT",
	"SHMDT",
    # Semaphores
    "SEMGET",
	"SEMCTL",
	"SEMOP",
	"SEMTIMEDOP",
    # Futexes
    "FUTEX",
	"SET_ROBUST_LIST",
	"GET_ROBUST_LIST",
    # System V message queue
    "MSGGET",
	"MSGCTL",
	"MSGSND",
	"MSGRCV",
    # POSIX message queue
    "MQ_OPEN",
	"MQ_UNLINK",
	"MQ_GETSETATTR",
	"MQ_TIMEDSEND",
	"MQ_TIMEDRECEIVE",
	"MQ_NOTIFY"
}

KEY_MANAGEMENT_SYSCALLS = {
    # Linux key management system calls
    "ADD_KEY",
	"REQUEST_KEY",
	"KEYCTL"
}
