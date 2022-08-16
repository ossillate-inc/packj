# <img src="https://www.svgrepo.com/show/255045/box-package.svg" width="45"/>&nbsp;<span style="font-size: 42px"> Packj flags malicious/risky open-source packages</span> 

*Packj* (pronounced package) is a command line (CLI) tool to vet open-source software packages for "risky" attributes that make them vulnerable to supply chain attacks. This is the tool behind our large-scale security analysis platform [Packj.dev](https://packj.dev) that continuously vets packages and provides free reports.

[![GitHub Stars](https://img.shields.io/github/stars/ossillate-inc/packj?style=social)](https://github.com/ossillate-inc/packj/stargazers) [![Discord](https://img.shields.io/discord/910733124558802974?label=Discord)](https://discord.gg/8hx3yEtF) ![](https://img.shields.io/badge/status-alpha-yellow) [![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0) [![Docker](https://badgen.net/badge/icon/docker?icon=docker&label)](https://hub.docker.com/r/ossillate/packj/tags)


# Contents #

* [How to use ](#how-to-use)
* [How it works](#how-it-works)
* [Risky attributes](#risky-attributes)
* [How to customize](#how-to-customize)
* [Talks and videos](#resources)
* [Malware found](#malware-found)
* [Project roadmap](#feature-roadmap)
* [Team and collaboration](#team)
* [FAQ](#faq)

# How to use #

Packj accepts the following input args:
* subcommand name, `audit` or `sandbox`
* name of the registry or package manager (e.g., pypi, npm, or rubygems)
* name of the package (e.g., requests, browserify, overcommit)
* optionally, package version string (e.g., 17.0.0). By default, the latest is picked.

## Auditing a package ##

Packj can audit PyPI, NPM, and RubyGems packages. It performs:
- static code analysis to check entire package code for use of filesystem, network, and process APIs (e.g., `connect`, `exec`),
- metadata analysis to check for attributes such as release timestamps, author email, downloads, dependencies, and 
- optionally, dynamic analysis to check the runtime behavior of the package (and all dependencies) by installing them analysing traces for system calls (e.g., `open()`, `fork()`). 

Packages with expired email domains, large release time gap, sensitive APIs, etc. are flagged as risky for [security reasons](#risky-attributes).

Packj also analyzes public repo code as well as metadata (e.g., stars, forks). By comparing the repo description and package title, you can be sure if the package indeed has been created from the repo to mitigate any `starjacking` attacks.

**NOTE** Dynamic tracing requires `--trace` option. We recommend to only use it for containerized runs (see usage below) as it installs a package, which could be malicious.

## Containerized

The best way to use Packj is to run it inside Docker (or Podman) container. **Remember** to always pull our latest image from DockerHub to get started: `docker pull ossillate/packj:latest`

**NOTE** that `-v /tmp:/tmp/packj` is needed for containerized runs under Docker so that final report is available under `/tmp` on the host. 

```
$ docker run -v /tmp:/tmp/packj ossillate/packj:latest audit --trace npm browserify
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

Specific package versions to be vetted could also be specified. Please refer to the example below

```
$ docker run -v /tmp:/tmp/packj ossillate/packj:latest audit pypi requests 2.18.4
[+] Fetching 'requests' from pypi...OK [ver 2.18.4]
[+] Checking version...ALERT [1750 days old]
[+] Checking release history...OK [142 version(s)]
[+] Checking release time gap...OK [14 days since last release]
[+] Checking author...OK [me@kennethreitz.org]
	[+] Checking email/domain validity...OK [me@kennethreitz.org]
[+] Checking readme...OK [49006 bytes]
[+] Checking homepage...OK [http://python-requests.org]
[+] Checking downloads...OK [50M weekly]
[+] Checking repo_url URL...OK [https://github.com/psf/requests]
	[+] Checking repo data...OK [stars: 47547, forks: 8758]
	[+] Checking repo activity...OK [commits: 6112, contributors: 725, tags: 144]
[+] Checking for CVEs...ALERT [2 found]
[+] Checking dependencies...OK [9 direct]
[+] Downloading package 'requests' (ver 2.18.4) from pypi...OK [123.27 KB]
[+] Analyzing code...ALERT [needs 4 perms: codegen,process,file,network]
[+] Checking files/funcs...OK [47 files (33 .py), 578 funcs, LoC: 13.9K]
=============================================
[+] 6 risk(s) found, package is undesirable, vulnerable!
{
    "undesirable": [
        "old package: 1744 days old",
        "invalid or no homepage: insecure webpage",
        "generates new code at runtime",
        "fetches data over the network", 
        "reads files and dirs",
    ], 
    "vulnerable": [
        "contains CVE-2018-18074,CVE-2018-18074"
    ]
}
=> Complete report: /tmp/pypi-requests-2.18.4.json
=> View pre-vetted package report at https://packj.dev/package/PyPi/requests/2.18.4
````

## Non-containerized

Alternatively, you can install Python/Ruby dependencies locally and test it.

**NOTE** 
* Packj has only been tested on Linux.
* Requires Strace, Python3, Ruby. API analysis will fail if used with Python2.
* You will have to install Python and Ruby dependencies before using the tool:
	- `pip install -r requirements.txt`
	- `gem install google-protobuf:3.21.2 rubocop:1.31.1`

```
$ python3 main.py audit npm eslint
[+] Fetching 'eslint' from npm...OK [ver 8.16.0]
[+] Checking version...OK [10 days old]
[+] Checking release history...OK [305 version(s)]
[+] Checking release time gap...OK [15 days since last release]
[+] Checking author...OK [nicholas+npm@nczconsulting.com]
	[+] Checking email/domain validity...OK [nicholas+npm@nczconsulting.com]
[+] Checking readme...OK [18234 bytes]
[+] Checking homepage...OK [https://eslint.org]
[+] Checking downloads...OK [23.8M weekly]
[+] Checking repo_url URL...OK [https://github.com/eslint/eslint]
	[+] Checking repo data...OK [stars: 20669, forks: 3689]
	[+] Checking repo activity...OK [commits: 8447, contributors: 1013, tags: 302]
[+] Checking for CVEs...OK [none found]
[+] Checking dependencies...ALERT [35 found]
[+] Downloading package 'eslint' (ver 8.16.0) from npm...OK [490.14 KB]
[+] Analyzing code...ALERT [needs 2 perms: codegen,file]
[+] Checking files/funcs...OK [395 files (390 .js), 1022 funcs, LoC: 76.3K]
=============================================
[+] 2 risk(s) found, package is undesirable!
{
    "undesirable": [
        "generates new code at runtime", 
        "reads files and dirs: ['package/lib/cli-engine/load-rules.js:37', 'package/lib/cli-engine/file-enumerator.js:142']"
    ]
}
=> Complete report: /tmp/npm-eslint-8.16.0.json
```

# How it works

- It first downloads the metadata from the registry using their APIs and analyze it for "risky" attributes.
- To perform API analysis, the package is downloaded from the registry using their APIs into a temp dir. Then, packj performs static code analysis to detect API usage. API analysis is based on [MalOSS](https://github.com/osssanitizer/maloss), a research project from our group at Georgia Tech.
- Vulnerabilities (CVEs) are checked by pulling info from OSV database at [OSV](https://osv.dev)
- Python PyPI and NPM package downloads are fetched from [pypistats](https://pypistats.org) and [npmjs](https://api.npmjs.org/downloads)
- Dynamic analysis is performed by installing the package under `strace` tool, which uses `ptrace` system calls underneath.
- All risks detected are aggregated and reported 

# Risky attributes #

The design of Packj is guided by our study of 651 malware samples of documented open-source software supply chain attacks. Specifically, we have empirically identified a number of risky code and metadata attributes that make a package vulnerable to supply chain attacks. 

For instance, we flag inactive or unmaintained packages that no longer receive security fixes. Inspired by Android app runtime permissions, Packj uses a permission-based security model to offer control and code transparency to developers. Packages that invoke sensitive operating system functionality such as file accesses and remote network communication are flagged as risky as this functionality could leak sensitive data.

Some of the attributes we vet for, include

| Attribute        |  Type    | Description                                              |  Reason                                                    |
|       :---:      |   :-:    |     :-:                                                  |   :-:                                                      |
|  Release date    | Metadata | Version release date to flag old or abandonded packages  | Old or unmaintained packages do not receive security fixes |
|  OS or lang APIs | Code     | Use of sensitive APIs, such as `exec` and `eval`         | Malware uses APIs from the operating system or language runtime to perform sensitive operations (e.g., read SSH keys) |
|  Contributors' email | Metadata | Email addresses of the contributors | Incorrect or invalid of email addresses suggest lack of 2FA |
|  Source repo | Metadata | Presence and validity of public source repo | Absence of a public repo means no easy way to audit or review the source code publicly |

Full list of the attributes we track can be viewed at [threats.csv](https://github.com/ossillate-inc/packj/blob/main/threats.csv)

These attributes have been identified as risky by several other researchers [[1](https://arxiv.org/pdf/2112.10165.pdf), [2](https://www.usenix.org/system/files/sec19-zimmermann.pdf), [3](https://www.ndss-symposium.org/wp-content/uploads/ndss2021_1B-1_23055_paper.pdf)] as well. 

# How to customize #

Packj has been developed with a goal to assist developers in identifying and reviewing potential supply chain risks in packages. 

However, since the degree of perceived security risk from an untrusted package depends on the specific security requirements, Packj can be customized according to your threat model. For instance, a package with no 2FA may be perceived to pose greater security risks to some developers, compared to others who may be more willing to use such packages for the functionality offered. Given the volatile nature of the problem, providing customized and granular risk measurement is one of our goals.

Packj can be customized to minimize noise and reduce alert fatigue by simply commenting out unwanted attributes in [threats.csv](https://github.com/ossillate-inc/packj/blob/main/threats.csv)

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

We welcome code contributions. Join our [discord community](https://discord.gg/8hx3yEtF) for discussion and feature requests.

# FAQ #

- _What Package Managers (Registries) are supported?_

Packj can currently vet NPM, PyPI, and RubyGems packages for "risky" attributes. We are adding support for Rust.

- _What techniques does Packj employ to detect risky/malicious packages?_

Packj uses static code analysis, dynamic tracing, and metadata analysis for comprehensive detection of malware. Static analysis parses package into  syntactical code components (e.g., functions, statements), which are analyzed for usage of sensitive language APIs (e.g., `JavaScript https.get` followed by `eval` that is typically used to download and execute malicious code). However, as the code is analyzed without execution during static analysis, Packj also performs dynamic analysis to capture runtime behavior of the package (and all dependencies). Finally, metadata analysis is carried out to check for several "risky" attributes (e.g., expired author email that implies lack of 2FA, lack of public source code repo or missing published version). Full list of the attributes we track can be viewed at [threats.csv](https://github.com/ossillate-inc/packj/blob/main/threats.csv)

- _Does this work at the system call level, where it would detect e.g. any attempt to open ~/.aws/credentials, or does it rely on heuristic analysis of the code itself, which will always be able to be "coded around" by the malware authors?_

Packj currently uses static analysis to analyze entire package code (programmatic behavior) and derive permissions needed (e.g., if the package accesses files or needs network access to communicate with a server). Therefore, it can detect `open()` or `connect()` calls if used by the malware directly (e.g., not obfuscated in a `base64` encoded string). But, Packj can also point out `base64` decode calls that are commonly leveraged to obfuscate malicious code. Fortunately, malware **has to** use these APIs (open, connect, decode, eval, etc.) for their functionality -- there's no getting around.

Having said that, a sophisticated malware can hide itself better to defeat our static analysis. Therefore, for comprehensive detection, Packj also performs dynamic analysis by installing the package under `strace` and monitoring it's runtime behavior. Collected traces are then analyzed for sensitive system calls (e.g., read files, spawn processes, network connections). Again, malware **has to** use these system calls in order to access system resources such as files/network stack.

- _Does it work on obfuscated calls? For example, a base 64 encrypted string that gets decrypted and then passed to a shell?_

This is a very common malicious behavior. Packj detects code obfuscation as well as spawning of shell commands (exec system call). For example, Packj can  flag use of `getattr()` and `eval()` API as they indicate "runtime code generation"; a developer can go and take a deeper look then. See [main.py](https://github.com/ossillate-inc/packj/blob/main/main.py#L488) for details.
