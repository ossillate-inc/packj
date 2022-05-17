# <img src="https://www.svgrepo.com/show/255045/box-package.svg" width="45"/>&nbsp;<span style="font-size: 42px"> Packj</span> 

*packj* (pronounced package) is a standalone command line (CLI) tool to vet open-source software packages for "risky" attributes that make them vulnerable to supply chain attacks.

## Usage

Packj accepts two input args:
* name of the registry or package manager, pypi or npm
* name of the package to be vetted

**NOTE** 
- Packj has only been tested on Linux. 
- You will have to install dependencies first using `pip install -r requirements.txt`
- Supports only Python2.7

```
$ python main.py pypi krisqian
[+] Fetching 'krisqian' from pypi...OK [ver 0.0.7]
[+] Checking author...OK [KrisWuQian@baidu.com]
[+] Checking version...OK [219 days old]
[+] Checking readme...OK [0 bytes]
[+] Checking repo...OK [None]
[+] Checking homepage...OK [https://www.bilibili.com/bangumi/media/md140632]
[+] Checking for CVEs...OK [0 found]
[+] Downloading package 'krisqian' (ver 0.0.7) from pypi...OK [1.94 KB]
[+] Analyzing APIs...OK
[+] 4 risk(s) found, package is undesirable!
{
    "undesirable": [
        "no source repo", 
        "generates new code at runtime", 
        "fetches data over the network ['KrisQian-0.0.7/setup.py:40', 'KrisQian-0.0.7/setup.py:50']", 
        "reads files and dirs: ['KrisQian-0.0.7/setup.py:59', 'KrisQian-0.0.7/setup.py:70']"
    ]
}
=> View pre-vetted package report at https://packj.dev/package/PyPi/KrisQian/0.0.7
```

Packj supports vetting of PyPI and NPM packages. **NOTE** NPM package vetting is a WIP.

```
$ python main.py npm eslint
[+] Fetching 'eslint' from npm...OK [ver 8.15.0]
[+] Checking author...OK [nicholas+npm@nczconsulting.com]
[+] Checking version...OK [4 days old]
[+] Checking readme...OK [18367 bytes]
[+] Checking homepage...OK [https://eslint.org]
[+] Checking repo...OK [git+https://github.com/eslint/eslint.git]
[+] Checking for CVEs...OK [0 found]
[+] Downloading package 'eslint' (ver 8.15.0) from npm...OK [489.42 KB]
[+] Analyzing APIs...OK
[+] 2 risk(s) found, package is undesirable!
{
    "undesirable": [
        "generates new code at runtime: generates new code at runtime", 
        "accesses files and dirs: reads files and dirs: ['package/lib/cli-engine/load-rules.js:37', 'package/lib/cli-engine/file-enumerator.js:142']"
    ]
}
```

Specific package versions to be vetted could be specified using `==`. Please refer to the example below

```
$ python main.py pypi requests==2.18.4
[+] Fetching 'requests' from pypi...OK [ver 2.18.4]
[+] Checking author...OK [me@kennethreitz.org]
[+] Checking version...OK [1711 days old]
[+] Checking readme...OK [49017 bytes]
[+] Checking repo...OK [https://github.com/psf/requests]
[+] Checking homepage...OK [http://python-requests.org]
[+] Checking for CVEs...OK [2 found]
[+] Downloading package 'requests' (ver 2.18.4) from pypi...OK [123.27 KB]
[+] Analyzing APIs...OK
[+] 6 risk(s) found, package is undesirable, vulnerable!
{
    "undesirable": [
        "1711 days old",
        "fetches data over the network", 
        "reads files and dirs", 
        "reads environment variables"
    ], 
    "vulnerable": [
        "contains CVE-2018-18074,CVE-2018-18074"
    ]
}
View pre-vetted package report at https://packj.dev/package/PyPi/requests/2.18.4
````

## How it works

- It first downloads the metadata from the registry using their APIs and analyze it for "risky" attributes.
- To perform API analysis, the package is downloaded from the registry using their APIs into a temp dir. Then, packj performs static code analysis to detect API usage. API analysis is based on [MalOSS](https://github.com/osssanitizer/maloss), a research project from our group at Georgia Tech.
- Vulnerabilities (CVEs) are checked by pulling info from OSV database at [OSV](https://osv.dev)
- All risks detected are aggregated and reported 

Refer to our [PyConUS'22 slides](https://speakerdeck.com/ashishbijlani/pyconus22-slides) for details.

## Risky attributes and customization

The design of Packj is guided by our study of 651 malware samples of documented open-source software supply chain attacks. Specifically, we have empirically identified a number of risky code and metadata attributes that make a package vulnerable to supply chain attacks. 

For instance, we flag inactive or unmaintained packages that no longer receive security fixes. Inspired by Android app runtime permissions, Packj uses a permission-based security model to offer control and code transparency to developers. Packages that invoke sensitive operating system functionality such as file accesses and remote network communication are flagged as risky as this functionality could leak sensitive data.

Some of the attributes we vet for, include

- Last version release date to rule out old or abandonded packages
- Use of sensitive APIs, such as `exec` and `eval`
- Correctness and validity of author email (for 2FA)
- Presence and validity of public source repo

Full list of such attributes can be viewed at [threats.csv](https://github.com/ossillate-inc/packj/blob/main/threats.csv)

Packj has been developed with a goal to assist developers in identifying and reviewing potential supply chain risks in packages. Since the degree of perceived security risk from an untrusted package depends on the specific security requirements, Packj can be customized according to the threat model of the user. For instance, a package with no 2FA may be perceived to pose greater security risks to some developers, compared to others who may be more willing to use such packages for the functionality offered. Given the volatile nature of the problem, providing customized and granular risk measurement is one of the goals of our tool. Packj can be customized to reduce alert fatigue by commenting out unwanted attributes in [threats.csv](https://github.com/ossillate-inc/packj/blob/main/threats.csv)

## Team

packj has been developed by cybersecurity researchers at [Ossillate Inc.](https://ossillate.com/team) to help developers mitigate risks of supply chain attacks when sourcing untrusted third-party open-source software dependencies.
