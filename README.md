# <img src="https://www.svgrepo.com/show/255045/box-package.svg" width="45"/>&nbsp;<span style="font-size: 42px"> Packj</span> 

*packj* (pronounced package) is a standalone tool to vet open-source software packages for "risky" attributes that make them vulnerable to supply chain attacks.

## Risky attributes

packj vets for several code and metadata attributes, including

- Use of sensitive APIs, such as ```exec``` 
- Correctness and validity of author email (for 2FA)
- Presence and validity of public source repo

packj has been developed by cybersecurity researchers at [Ossillate Inc.](https://ossillate.com) to help developers mitigate risks of supply chain attacks when sourcing untrusted third-party open-source software dependencies.

## Usage

```
$ python main.py pypi KrisQian
[+] Fetching 'KrisQian' from pypi...OK [ver 0.0.7]
[+] Checking author...OK [KrisWuQian@baidu.com]
[+] Checking version...OK [217 days old]
[+] Checking readme...OK [0 bytes]
[+] Checking repo...OK [None]
[+] Checking homepage...OK [https://www.bilibili.com/bangumi/media/md140632]
[+] Checking for CVEs...OK [0 found]
[+] Downloading package 'KrisQian' (ver 0.0.7) from pypi...OK [1.94 KB]
[+] Analyzing APIs...OK
[+] 4 risk(s) found, package is undesirable!
{
    "undesirable": [
        "no description", 
        "no source repo", 
        "fetches data over the network", 
        "reads files and dirs"
    ]
}
=> View detailed and complete report at https://packj.dev/package/PyPi/KrisQian/0.0.7
````
