# <img src="https://www.svgrepo.com/show/255045/box-package.svg" width="45"/>&nbsp;<span style="font-size: 42px"> Packj flags malicious/risky open-source packages</span> 

*Packj* (pronounced package) is a command line (CLI) tool to vet open-source software packages for "risky" attributes that make them vulnerable to supply chain attacks. This is the tool behind our large-scale security analysis platform [Packj.dev](https://packj.dev) that continuously vets packages and provides free reports.

[![GitHub Stars](https://img.shields.io/github/stars/ossillate-inc/packj?style=social)](https://github.com/ossillate-inc/packj/stargazers) [![Discord](https://img.shields.io/discord/910733124558802974?label=Discord)](https://discord.gg/8hx3yEtF)

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

Packj accepts two input args:
* name of the registry or package manager, pypi, npm, or rubygems.
* name of the package to be vetted

Packj supports vetting of PyPI, NPM, and RubyGems packages. It performs static code analysis and checks for several metadata attributes such as release timestamps, author email, downloads, dependencies. Packages with expired email domains, large release time gap, sensitive APIs, etc. are flagged as risky for [security reasons](#risky-attributes).

Packj also analyzes public repo code as well as metadata (e.g., stars, forks). By comparing the repo description and package title, you can be sure if the package indeed has been created from the repo to mitigate any `starjacking` attacks.

## Containerized

The best way to use Packj is to run it inside Docker (or Podman). You can use the latest Docker image.

`docker run --mount type=bind,source=/tmp,target=/tmp ossillate/packj:latest`


```
$ docker run --mount type=bind,source=/tmp,target=/tmp ossillate/packj:latest npm browserify
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
=============================================
[+] 5 risk(s) found, package is undesirable!
=> Complete report: /tmp/npm-browserify-17.0.0.json
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

Specific package versions to be vetted could be specified using `==`. Please refer to the example below

```
$ docker run --mount type=bind,source=/tmp,target=/tmp ossillate/packj:latest pypi requests==2.18.4
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
* Requires Python3 and Ruby. API analysis will fail if used with Python2.
* You will have to install Python and Ruby dependencies before using the tool:
	- `pip install -r requirements.txt`
	- `gem install google-protobuf:3.21.2 rubocop:1.31.1`

```
$ python3 main.py npm eslint
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
=> Complete report: npm-eslint-8.16.0.json
```

# How it works

- It first downloads the metadata from the registry using their APIs and analyze it for "risky" attributes.
- To perform API analysis, the package is downloaded from the registry using their APIs into a temp dir. Then, packj performs static code analysis to detect API usage. API analysis is based on [MalOSS](https://github.com/osssanitizer/maloss), a research project from our group at Georgia Tech.
- Vulnerabilities (CVEs) are checked by pulling info from OSV database at [OSV](https://osv.dev)
- Python PyPI and NPM package downloads are fetched from [pypistats](https://pypistats.org) and [npmjs](https://api.npmjs.org/downloads)
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
$ python3 main.py pypi krisqian
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
- Academic [dissertation](https://cyfi.ece.gatech.edu/publications/DUAN-DISSERTATION-2019.pdf) on open-source software security and the [paper](https://www.ndss-symposium.org/wp-content/uploads/ndss2021_1B-1_23055_paper.pdf) from our group at Georgia Tech that started this research.

# Feature roadmap #

* Add support for other language ecosystems. Ruby is a work in progress, and will be available in July '22 (first week).
* Add functionality to detect several other "risky" code as well as metadata attributes.
* Packj currently only performs static code analysis, we are working on adding support for dynamic analysis (ETA: end of summer)

# Team #

Packj has been developed by Cybersecurity researchers at [Ossillate Inc.](https://ossillate.com/team) and external collaborators to help developers mitigate risks of supply chain attacks when sourcing untrusted third-party open-source software dependencies. We thank our developers and collaborators.

- [Dr. Ashish Bijlani](https://github.com/ashishbijlani)
- [Devdutt Patnaik](https://github.com/DevP17)
- [Ajinkya Rajput](https://github.com/the-elves)
- [Lucas Zhang](https://github.com/LucasZhang58)
- [Shubham Thakur](https://github.com/sbmthakur)
- [Dr. Ruian Duan](https://github.com/lingfennan)

We welcome code contributions. Join our [discord community](https://discord.gg/8hx3yEtF) for discussion and feature requests.

# FAQ #

- _Does it work on obfuscated calls? For example, a base 64 encrypted string that gets decrypted and then passed to a shell?_

This is a very common malicious behavior. Packj detects code obfuscation as well as spawning of shell commands (exec system call). For example, Packj can  flag use of `getattr()` and `eval()` API as they indicate "runtime code generation"; a developer can go and take a deeper look then. See [main.py](https://github.com/ossillate-inc/packj/blob/main/main.py#L486) for details.

- _Does this work at the system call level, where it would detect e.g. any attempt to open ~/.aws/credentials, or does it rely on heuristic analysis of the code itself, which will always be able to be "coded around" by the malware authors?_

Packj currently uses static code analysis to derive permissions (e.g., file/network accesses). Therefore, it can detect open() calls if used by the malware directly (e.g., not obfuscated in a base64 encoded string). But, Packj can also point out such base64 decode calls. Fortunately, malware has to use these APIs (read, open, decode, eval, etc.) for their functionality -- there's no getting around. Having said that, a sophisticated malware can hide itself better, so dynamic analysis must be performed for completeness. We are incorporating strace-based dynamic analysis (containerized) to collect system calls. See [roadmap](#feature-roadmap) for details.
