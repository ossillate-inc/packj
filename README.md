# <img src="https://raw.githubusercontent.com/feathericons/feather/master/icons/package.svg" width="45"/>&nbsp;<span style="font-size: 42px"> Packj flags malicious/risky open-source packages</span> 

*Packj* (pronounced package) is a suite of command line (CLI) tools to mitigate software supply chain attacks. Specifically, it flags malicious and other "risky" packages in popular open-source package registries, such as NPM, RubyGems, and PyPI. This is the tool behind our large-scale security analysis platform [Packj.dev](https://packj.dev) that continuously vets packages and provides free risk assessment reports.

[![GitHub Stars](https://img.shields.io/github/stars/ossillate-inc/packj?style=social)](https://github.com/ossillate-inc/packj/stargazers) [![Discord](https://img.shields.io/discord/910733124558802974?label=Discord)](https://discord.gg/8hx3yEtF) ![](https://img.shields.io/badge/status-alpha-yellow) [![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0) [![Docker](https://badgen.net/badge/icon/docker?icon=docker&label)](https://hub.docker.com/r/ossillate/packj/tags)


# Contents #

* [Get started ](#get-started)
* [Malware found](#malware-found)
* [Talks and videos](#resources)
* [Project roadmap](#feature-roadmap)
* [Team and collaboration](#team)
* [FAQ](#faq)

# Get started #

Packj offers the following tools: 

* [Audit](#auditing-a-package) - to vet a package for "risky" attributes.
* [Sandbox](#sandboxed-package-installation) - for safe installation of a package.

```
$ python3 main.py --help
usage: main [options] args

options:
    audit          Audit a package for malware/risky attributes
    sandbox        Sandbox package installation to mitigate risks
```

## Auditing a package ##

Packj audits open-source software packages for "risky" attributes that make them vulnerable to supply chain attacks. For instance, packages with expired email domains (lacking 2FA), large release time gap, sensitive APIs or access permissions, etc. are flagged as risky. 

Please find details on risky attributes and how to use at [Audit README](https://github.com/ossillate-inc/packj/blob/main/audit/README.md).

```
$ python3 main.py audit npm browserify

[+] Fetching 'browserify' from npm...OK [ver 17.0.0]
[+] Checking version...ALERT [598 days old]
[+] Checking release history...OK [484 version(s)]
[+] Checking release time gap...OK [68 days since last release]
[+] Checking author...OK [mail@substack.net]
	[+] Checking email/domain validity...ALERT [expired author email domain]
[+] Checking readme...OK [26838 bytes]
[+] Checking homepage...OK [https://github.com/browserify/browserify#readme]
[+] Checking downloads...OK [2.2M weekly]
[+] Checking repo_url URL...OK [https://github.com/browserify/browserify]
	[+] Checking repo data...OK [stars: 14077, forks: 1236]
	[+] Checking repo activity...OK [commits: 2290, contributors: 207, tags: 413]
[+] Checking for CVEs...OK [none found]
[+] Checking dependencies...ALERT [48 found]
[+] Downloading package 'browserify' (ver 17.0.0) from npm...OK [163.83 KB]
[+] Analyzing code...ALERT [needs 3 perms: process,file,codegen]
[+] Checking files/funcs...OK [429 files (383 .js), 744 funcs, LoC: 9.7K]
[+] Installing package and tracing code...OK [found ['process', 'files', 'network'] syscalls]
=============================================
[+] 5 risk(s) found, package is undesirable!

=> Complete report: /tmp/packj_54rbjhgm/report_npm-browserify-17.0.0_hlr1rhcz.json
{
    "undesirable": [
        "old package: 598 days old",
        "invalid or no author email: expired author email domain",
        "generates new code at runtime", 
        "reads files and dirs",
        "forks or exits OS processes",
    ]
}
```

## Sandboxed package installation ##

Packj offers a lightweight sandboxing for `safe installation` of a package. Specifically, it prevents malicious packages from exfiltrating sensitive data, accessing sensitive files (e.g., SSH keys), and persisting malware.

Please find details on the sandboxing mechanism and how to use at [Sandbox README](https://github.com/ossillate-inc/packj/blob/main/sandbox/README.md).

```
$ python3 main.py sandbox gem install overcommit

Fetching: overcommit-0.59.1.gem (100%)
Install hooks by running `overcommit --install` in your Git repository
Successfully installed overcommit-0.59.1
Parsing documentation for overcommit-0.59.1
Installing ri documentation for overcommit-0.59.1

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

# Malware found #

We found over 40 malicious packages on PyPI using this tool. A number of them been taken down. Refer to an example below:

```
$ python3 main.py audit pypi krisqian
[+] Fetching 'krisqian' from pypi...OK [ver 0.0.7]
[+] Checking version...OK [256 days old]
[+] Checking release history...OK [7 version(s)]
[+] Checking release time gap...OK [1 days since last release]
[+] Checking author...OK [KrisWuQian@baidu.com]
	[+] Checking email/domain validity...OK [KrisWuQian@baidu.com]
[+] Checking readme...ALERT [no readme]
[+] Checking homepage...OK [https://www.bilibili.com/bangumi/media/md140632]
[+] Checking downloads...OK [13 weekly]
[+] Checking repo_url URL...OK [None]
[+] Checking for CVEs...OK [none found]
[+] Checking dependencies...OK [none found]
[+] Downloading package 'KrisQian' (ver 0.0.7) from pypi...OK [1.94 KB]
[+] Analyzing code...ALERT [needs 3 perms: process,network,file]
[+] Checking files/funcs...OK [9 files (2 .py), 6 funcs, LoC: 184]
=============================================
[+] 6 risk(s) found, package is undesirable!
{
    "undesirable": [
        "no readme",
        "only 45 weekly downloads",
        "no source repo found", 
        "generates new code at runtime", 
        "fetches data over the network: ['KrisQian-0.0.7/setup.py:40', 'KrisQian-0.0.7/setup.py:50']", 
        "reads files and dirs: ['KrisQian-0.0.7/setup.py:59', 'KrisQian-0.0.7/setup.py:70']"
    ]
}
=> Complete report: pypi-KrisQian-0.0.7.json
=> View pre-vetted package report at https://packj.dev/package/PyPi/KrisQian/0.0.7
```

Packj flagged KrisQian (v0.0.7) as suspicious due to absence of source repo and use of sensitive APIs (network, code generation) during package installation time (in setup.py). We decided to take a deeper look, and found the package malicious. Please find our detailed analysis at [https://packj.dev/malware/krisqian](https://packj.dev/malware/krisqian).

More examples of malware we found are listed at [https://packj.dev/malware](https://packj.dev/malware) Please reach out to us at [oss@ossillate.com](mailto:oss@ossillate.com) for full list.

# Resources #

To learn more about Packj tool or open-source software supply chain attacks, refer to our

[![PyConUS'22 Video](https://img.youtube.com/vi/Rcuqn56uCDk/0.jpg)](https://www.youtube.com/watch?v=Rcuqn56uCDk)

- PyConUS'22 [talk](https://www.youtube.com/watch?v=Rcuqn56uCDk) and [slides](https://speakerdeck.com/ashishbijlani/pyconus22-slides).
- BlackHAT Asia'22 Arsenal [presentation](https://www.blackhat.com/asia-22/arsenal/schedule/#mitigating-open-source-software-supply-chain-attacks-26241)
- PackagingCon'21 [talk](https://www.youtube.com/watch?v=PHfN-NrUCoo) and [slides](https://speakerdeck.com/ashishbijlani/mitigating-open-source-software-supply-chain-attacks)
- BlackHat USA'22 Arsenal talk [Detecting typo-squatting, backdoored, abandoned, and other "risky" open-source packages using Packj](https://www.blackhat.com/us-22/arsenal/schedule/#detecting-typo-squatting-backdoored-abandoned-and-other-risky-open-source-packages-using-packj-28075)
- Academic [dissertation](https://cyfi.ece.gatech.edu/publications/DUAN-DISSERTATION-2019.pdf) on open-source software security and the [paper](https://www.ndss-symposium.org/wp-content/uploads/ndss2021_1B-1_23055_paper.pdf) from our group at Georgia Tech that started this research.

### Upcoming talks ###

- Open Source Summit, Europe'22 talk [Scoring dependencies to detect “weak links” in your open-source software supply chain](https://osseu2022.sched.com/overview/type/SupplyChainSecurityCon)
- NullCon'22 talk [Unearthing Malicious And Other “Risky” Open-Source Packages Using Packj](https://nullcon.net/goa-2022/unearthing-malicious-and-other-risky-open-source-packages-using-packj)

# Feature roadmap #

* Add support for other language ecosystems. Rust is a work in progress, and will be available in August '22 (last week).
* Add functionality to detect several other "risky" code as well as metadata attributes.
* Add support for sandboxed installation of packages (WIP, ETA: end of summer)

# Team #

Packj has been developed by Cybersecurity researchers at [Ossillate Inc.](https://ossillate.com/team) and external collaborators to help developers mitigate risks of supply chain attacks when sourcing untrusted third-party open-source software dependencies. We thank our developers and collaborators.

We welcome code contributions with open arms. Please join our [discord community](https://discord.gg/8hx3yEtF) for discussion and feature requests.

# FAQ #

- _What Package Managers (Registries) are supported?_

Packj can currently vet NPM, PyPI, and RubyGems packages for "risky" attributes. We are adding support for Rust.

- _What techniques does Packj employ to detect risky/malicious packages?_

Packj uses static code analysis, dynamic tracing, and metadata analysis for comprehensive auditing. Static analysis alone is not sufficient to flag sophisticated malware that can hide itself better using code obfuscation. Dynamic analysis is performed by installing the package under `strace` and monitoring it's runtime behavior. Please read more at [Audit README](https://github.com/ossillate-inc/packj/blob/main/audit/README.md).

- _Does it work on obfuscated calls? For example, a base 64 encrypted string that gets decrypted and then passed to a shell?_

This is a very common malicious behavior. Packj detects code obfuscation as well as spawning of shell commands (exec system call). For example, Packj can  flag use of `getattr()` and `eval()` API as they indicate "runtime code generation"; a developer can go and take a deeper look then. See [main.py](https://github.com/ossillate-inc/packj/blob/audit/main.py#L488) for details.
