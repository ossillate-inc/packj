from enum import Enum


class PackageManagerEnum(Enum):
    # Reference: http://www.modulecounts.com
    pypi = 'pypi'
    npmjs = 'npmjs'
    rubygems = 'rubygems'
    maven = 'maven'
    jcenter = 'jcenter'
    jitpack = 'jitpack'
    nuget = 'nuget'
    packagist = 'packagist'
    dockerhub = 'dockerhub'
    rust = 'cargo'

    # Local package
    local_nodejs = 'local_nodejs'
    local_python = 'local_python'

    # TODO: add support for these
    # Reference: https://github.com/showcases/package-managers?s=stars
    vagrantcloud = 'vagrantcloud'  # for vagrant
    debian = 'debian'  # for debian
    ubuntu = 'ubuntu'  # for ubuntu
    aur = 'aur'  # for arch linux
    yum = 'yum'  # for centos/fedora
    cpan = 'cpan'  # for perl
    cran = 'cran'  # for R
    glide = 'glide'  # for Golang
    swift_pm = 'swift_pm'  # for swift
    launchpad = 'launchpad'  # for ubuntu packages, https://launchpad.net/projects/+all
    # bower, yarn and webpack is frontend for the web

    def __str__(self):
        return self.value


class LanguageEnum(Enum):
    # In correspondence to PackageManager class in crawl.py
    python = 'python'
    javascript = 'javascript'
    ruby = 'ruby'
    java = 'java'
    csharp = 'csharp'
    php = 'php'
    docker = 'docker'
    vagrant = 'vagrant'
    rust = 'rust'

    def __str__(self):
        return self.value


class DistanceAlgorithmEnum(Enum):
    py_edit_distance = 'py_edit_distance'
    c_edit_distance = 'c_edit_distance'
    c_edit_distance_batch = 'c_edit_distance_batch'

    # TODO: add more algorithms
    def __str__(self):
        return self.value


class SyscallEnum(Enum):
    file = "FILE"
    network = "NETWORK"
    process = "PROCESS"
    time = "TIME"
    signal = "SIGNAL"
    ipc = "IPC"
    key_management = "KEY_MANAGEMENT"

    def __str__(self):
        return self.value


class TraceTypeEnum(Enum):
    strace = "strace"
    sysdig = "sysdig"

    # FIXME: not supported
    dtrace = "dtrace"
    ftrace = "ftrace"
    procmon = "procmon"
    pytrace = "pytrace"

    def __str__(self):
        return self.value


class DataTypeEnum(Enum):
    # metadata
    reverse_dep = "reverse_dep"

    # static
    author = "author"
    dependency = "dependency"
    api = "api"
    permission = "permission"
    taint = "taint"
    compare_ast = "compare_ast"

    # dynamic
    domain = "domain"
    ip = "ip"
    file = "file"
    process = "process"
    sensitive = "sensitive"

    # combined
    install_with_network = "install_with_network"
    correlate_info_api_compare_ast = "correlate_info_api_compare_ast"

    def __str__(self):
        return self.value


class FalcoRuleEnum(Enum):
    """
    Unexpected behaviors, defined and flagged as falco rules
    """
    # network connections
    outgoing_domain = "outgoing_domain"
    incoming_domain = "incoming_domain"
    outgoing_ip = "outgoing_ip"
    incoming_ip = "incoming_ip"

    # files
    # write/remove unexpected file
    write_file = "write_file"
    # read sensitive file
    read_file = "read_file"
    # stat files, for circumvention or environment check
    stat_file = "stat_file"

    # processes, e.g. shell process, fields are: user, proc.name, proc.cmdline
    spawn_process = "spawn_process"

    # sensitive or privilege operations, fields are: user, proc.cmdline, evt.type
    sensitive_operation = "sensitive_operation"

    def __str__(self):
        return self.value
