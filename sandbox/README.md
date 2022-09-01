# Package installation sandbox #

Cybersecurity researchers [found](https://arxiv.org/pdf/2112.10165.pdf) that 93.9% of malicious packages use at least one install script. Packj offers a lightweight sandboxing and isolated environment for `safe installation` of a package. 

The sandbox prevents malicious packages from exfilterating sensitive data, accessing sensitive files (e.g., SSH keys), and persisting malware.

## Contents ##

* [How to use](#how-to-use)
* [How it works](#how-it-works)
* [How to customize](#how-to-customize)
* [FAQ](#faq)

## How to use ##

Packj supports PyPI, NPM, and RubyGems package registries. To safely install a package, you need to provide the folowing command line arguments:

```
$ python3 main.py sandbox <pm-tool> install <pkg-name> [<ver-str> <other args>]

arguments:
  pm_tool       Package manager CLI tool (e.g., pip3, gem, npm)
  pkg_name      Install args (e.g., package name, version, other args)
```

## How it works ##

Packj sandbox creates a network firewall and an isolated filesystem layer by interposing on system calls (e.g., `open`, `connect`) with [strace](https://github.com/strace/strace) and re-writing system calls arguments (e.g., file path) as per the sandboxing rules in `packj.yaml`. Rewriting ensures that all file system modifications are confined to the isolated layer. As a result, the requested package is **ONLY** installed in the sandboxed file system. All network and file system activities are logged. At the end, the user can review these activities before commiting to the host filesystem to **actually** install the package (i.e., copy artifacts).

```
$ python3 main.py sandbox gem install overcommit

Fetching: childprocess-4.1.0.gem (100%)
Successfully installed childprocess-4.1.0
Fetching: iniparse-1.5.0.gem (100%)
Successfully installed iniparse-1.5.0
Fetching: rexml-3.2.5.gem (100%)
Successfully installed rexml-3.2.5
Fetching: overcommit-0.59.1.gem (100%)
Install hooks by running `overcommit --install` in your Git repository
Successfully installed overcommit-0.59.1
Parsing documentation for childprocess-4.1.0
Installing ri documentation for childprocess-4.1.0
Parsing documentation for iniparse-1.5.0
Installing ri documentation for iniparse-1.5.0
Parsing documentation for rexml-3.2.5
Installing ri documentation for rexml-3.2.5
Parsing documentation for overcommit-0.59.1
Installing ri documentation for overcommit-0.59.1
Done installing documentation for childprocess, iniparse, rexml, overcommit after 3 seconds
4 gems installed

#############################
# Review summarized activity
#############################

[+] Network connections
	[+] DNS (1 IPv4 addresses) at port 53 [rule: ALLOW]
	[+] rubygems.org (4 IPv6 addresses) at port 443 [rule: IPv6 rules not supported]
	[+] rubygems.org (4 IPv4 addresses) at port 443 [rule: ALLOW]
[+] Filesystem changes
/
└── home
    └── ubuntu
        └── .ruby
            ├── gems
            │   ├── iniparse-1.5.0 [new: DIR, 15 files, 46.6K bytes]
            │   ├── rexml-3.2.5 [new: DIR, 77 files, 455.6K bytes]
            │   ├── overcommit-0.59.1 [new: DIR, 252 files, 432.7K bytes]
            │   └── childprocess-4.1.0 [new: DIR, 57 files, 141.2K bytes]
            ├── cache
            │   ├── iniparse-1.5.0.gem [new: FILE, 16.4K bytes]
            │   ├── rexml-3.2.5.gem [new: FILE, 93.2K bytes]
            │   ├── childprocess-4.1.0.gem [new: FILE, 34.3K bytes]
            │   └── overcommit-0.59.1.gem [new: FILE, 84K bytes]
            ├── specifications
            │   ├── rexml-3.2.5.gemspec [new: FILE, 2.7K bytes]
            │   ├── overcommit-0.59.1.gemspec [new: FILE, 1.7K bytes]
            │   ├── childprocess-4.1.0.gemspec [new: FILE, 1.8K bytes]
            │   └── iniparse-1.5.0.gemspec [new: FILE, 1.3K bytes]
            ├── bin
            │   └── overcommit [new: FILE, 622 bytes]
            └── doc
                ├── iniparse-1.5.0
                │   └── ri [new: DIR, 119 files, 131.7K bytes]
                ├── rexml-3.2.5
                │   └── ri [new: DIR, 836 files, 841K bytes]
                ├── overcommit-0.59.1
                │   └── ri [new: DIR, 1046 files, 1.5M bytes]
                └── childprocess-4.1.0
                    └── ri [new: DIR, 272 files, 297.8K bytes]

[C]ommit all changes, [Q|q]uit & discard changes, [L|l]ist details:
```

# How to customize #

Sandboxing rules from `packj.yaml` are applied to allow/block network access or allow/hide sensitive file system paths. By default, only a few domains are allowed; please customize to fit your use case by simply editing rules in [packj.yaml](https://github.com/ossillate-inc/packj/blob/main/packj.yaml)

# FAQ #

- _How is this sandbox different from existing techniques (e.g., Docker, chroot)?_

Docker and `chroot` also offer an isolated file system. However, the file system is completely new (i.e., the root mount point is new). Therefore, for compatibility and to be able to safely copy artifacts back to the host after installation, this new file system must be an exact replica of the host file system. For example, a number of packages contain native extensions, which require complex compilation steps and rely heavily on system dependencies. Such packages will break if the host file system is different from the sandbox. Packj adopts Copy-on-Write (COW) approach to isolate file system changes in a new layer by rewriting system call arguments on the fly. At the end of the package installation process, once the changes are reviwed and committed, the new layer is merged with the host file system, thereby offering the system state.
