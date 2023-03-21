# <img src="https://packj.dev/static/img/icons/package.svg" width="45"/>&nbsp;<span style="font-size: 42px"> Packj flags malicious/risky open-source packages</span> 

*Packj* (pronounced package) is a tool to detect software supply chain attacks. It can detect malicious, vulnerable, abandoned, typo-squatting, and other "risky" packages from popular open-source package registries, such as NPM, RubyGems, and PyPI. It can be easily customized to minimize noise. Packj started as a PhD research project and is currently being developed under various govt grants.

[![GitHub Stars](https://img.shields.io/github/stars/ossillate-inc/packj?style=social)](https://github.com/ossillate-inc/packj/stargazers) ![](https://img.shields.io/badge/status-beta-yellow) [![Prs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=shields)](https://github.com/ossillate-inc/packj/blob/main/CONTRIBUTING.md) ![Github Commit Activity](https://img.shields.io/github/commit-activity/m/ossillate-inc/packj) [![Discord](https://img.shields.io/discord/910733124558802974?label=Discord)](https://discord.gg/qFcqaV2wYa)  [![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0) [![Docker](https://badgen.net/badge/icon/docker?icon=docker&label)](https://hub.docker.com/r/ossillate/packj/tags)
[![PyPI - Downloads](https://img.shields.io/pypi/dm/packj?label=PyPI%20Downloads)](https://pypistats.org/packages/packj)

> **Note**
**Self-hosted Packj webserver and several integrations coming later this month :punch: Watch this repo to stay up to date.**

![demo video](https://drive.google.com/uc?export=view&id=1QfA73i_ihgqo2JbNXoxaGSZ2Wa02RZNq)

# Contents #

* [Get started](#get-started) - available as Docker image, GitHub Action, Python PyPI package
* [Functionality](#functionality) - deep static/dynamic code analysis and sandboxing
* [Our story](#our-story) - started as a PhD research project and is backed by govt grants
* [Why Packj](#why-packj) - existing CVE scanners ASSUME code is BENIGN and not analyze its behavior
* [Customization](#customization) - turn off alerts as per your threat model to reduce noise
* [Malware found](#malware-found) - reported over 70 malicious PyPI and RubyGems packages
* [Talks and videos](#resources) - presentations from PyCon, OpenSourceSummit, BlackHAT
* [Project roadmap](#feature-roadmap) - view or suggest new features; join our [discord channel](https://discord.gg/qFcqaV2wYa)
* [Team and collaboration](#team-and-contributors) - lead by Cybersecurity researchers from academia/industry
* [FAQ](#faq) - supported package managers, commonly asked questions on techniques, and more

# Get started #

We support multiple deployment models:

### 1. GitHub runner 

Use Packj to audit dependencies in pull requests.

```yaml
- name: Packj Security Audit
  uses: ossillate-inc/packj-github-action@0.0.4-beta
  with:
    # TODO: replace with your dependency files in the repo
    DEPENDENCY_FILES: pypi:requirements.txt,npm:package.json,rubygems:Gemfile
    REPO_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

View on GitHub [marketplace](https://packj.dev/go?next=https://github.com/marketplace/actions/packj-security-audit). Example [PR run](https://packj.dev/go?next=https://github.com/ossillate-inc/packj-github-action-demo/pull/3#issuecomment-1274797138).

###  2. PyPI package

The quickest way to try/test Packj is using the PyPI package.

>
> **Warning**: Packj only works on Linux.
>

```
pip3 install packj
```

Auditing RubyGems require additional dependencies

```
bundle install
```

### 3. Docker image (recommended)

Use Docker or Podman for containerized (isolated) runs.

```
docker run -v /tmp:/tmp/packj -it ossillate/packj:latest --help
```

### 4. Source repo

Clone this repo, 

```
https://github.com/ossillate-inc/packj.git && cd packj
```

Install dependencies

```
bundle install && pip3 install -r requirements.txt
```

Start with help:

```
python3 main.py --help 
```

# Functionality #

Packj offers the following tools: 

* [Audit](#auditing-a-package) - to vet a package for "risky" attributes.
* [Sandbox](#sandboxed-package-installation) - for safe installation of a package. 

## Auditing a package ##

Packj audits open-source software packages for "risky" attributes that make them vulnerable to supply chain attacks. For instance, packages with expired email domains (lacking 2FA), large release time gap, sensitive APIs or access permissions, etc. are flagged as risky. 

Auditing the following is supported:

- multiple packages: `python3 main.py audit -p pypi:requests rubygems:overcommit`
- dependency files: `python3 main.py audit -f npm:package.json pypi:requirements.txt`

By default, `audit` only performs static code analysis to detect risky code. You can paas `-t` or `--trace` flag to perform dynamic code analysis as well, which will install all requested packages under strace and monitor install-time behavior of packages. Please see the example output below.

<details>
    <summary><h4>Show example run/output</h4></summary>

    $ docker run -v /tmp:/tmp/packj -it ossillate/packj:latest audit --trace -p npm:browserify

    [+] Fetching 'browserify' from npm..........PASS [ver 17.0.0]
    [+]    Checking package description.........PASS [browser-side require() the node way]
    [+]    Checking release history.............PASS [484 version(s)]
    [+] Checking version........................RISK [702 days old]
    [+]    Checking release time gap............PASS [68 days since last release]
    [+] Checking author.........................PASS [mail@substack.net]
    [+]    Checking email/domain validity.......RISK [expired author email domain]
    [+] Checking readme.........................PASS [26838 bytes]
    [+] Checking homepage.......................PASS [https://github.com/browserify/browserify#readme]
    [+] Checking downloads......................PASS [2M weekly]
    [+] Checking repo URL.......................PASS [https://github.com/browserify/browserify]
    [+]    Checking repo data...................PASS [stars: 14189, forks: 1244]
    [+]    Checking if repo is a forked copy....PASS [original, not forked]
    [+]    Checking repo description............PASS [browser-side require() the node.js way]
    [+]    Checking repo activity...............PASS [commits: 2290, contributors: 207, tags: 413]
    [+] Checking for CVEs.......................PASS [none found]
    [+] Checking dependencies...................RISK [48 found]
    [+] Downloading package from npm............PASS [163.83 KB]
    [+] Analyzing code..........................RISK [needs 3 perm(s): decode,codegen,file]
    [+] Checking files/funcs....................PASS [429 files (383 .js), 744 funcs, LoC: 9.7K]
    [+] Installing package and tracing code.....PASS [found 5 process,1130 files,22 network syscalls]
    =============================================
    [+] 5 risk(s) found, package is undesirable!
    => Complete report: /tmp/packj_54rbjhgm/report_npm-browserify-17.0.0_hlr1rhcz.json
    {
        "undesirable": [
            "old package: 702 days old",
            "invalid or no author email: expired author email domain",
            "generates new code at runtime",
            "reads files and dirs",
            "forks or exits OS processes",
        ]
    }
</details>

> WARNING: since packages could execute malicious code during installation, it is recommended to ONLY use `-t` or `--trace` when running inside a Docker container or a Virtual Machine.

Audit can also be performed in Docker/Podman containers. Please find details on risky attributes and how to use at [Audit README](https://packj.dev/go?next=https://github.com/ossillate-inc/packj/blob/main/packj/audit/README.md).

## Sandboxed package installation ##

Packj offers a lightweight sandboxing for `safe installation` of a package. Specifically, it prevents malicious packages from exfiltrating sensitive data, accessing sensitive files (e.g., SSH keys), and persisting malware. 

It sandboxes install-time scripts, including any native compliation. It uses **strace** (i.e., **NO** VM/Container required).

Please find details on the sandboxing mechanism and how to use at [Sandbox README](https://packj.dev/go?next=https://github.com/ossillate-inc/packj/blob/main/packj/sandbox/README.md).

<details>
    <summary><h4>Show example run/output</h4></summary>

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
</details>

# Our story

**TL;DR** Packj started as a PhD research project. It is backed by various government grants.

<details>
	<summary><h4>Show long answer</h4></summary>

Packj started as an academic research project. Specifically, the static code analysis techniques used by Packj are based on cutting-edge Cybersecurity research: [MalOSS](https://packj.dev/go?next=https://github.com/osssanitizer/maloss) project by our research [group](https://packj.dev/go?next=http://cyfi.ece.gatech.edu) at Georgia Tech.

<a href="https://packj.dev/go?next=https://arxiv.org/pdf/2002.01139v1.pdf" target="_blank">
	<img src="https://drive.google.com/uc?export=view&id=1L03-kFTdNDFvGLWt_zJ-Qe8PPX75ICqo" width="300" alt="academic paper">
</a>

Packj is backed by generous grants from [NSF](https://www.sbir.gov/node/2083473), [GRA](https://gra.org/company/227/OSSPolice.html), and [ALInnovate](https://innovatealabama.org).

</details>

# Why Packj

**TL;DR** The state-of-the-art vulnerability scanners assume that the third-party open-source code is BENIGN. Therefore, all such tools ONLY address threats from accidental programming bugs in benign code (a.k.a. CVEs such as Log4J). They DO NOT protect against Solarwinds-like modern software supply-chain attacks from deliberately bad (a.k.a. malicious) code that is propagated by bad actors using new vulnerabilities in the supply channel, including dependency confusion, typo-squatting, protestware (sabotaging), account hijacking, and social engineering. A recent (Dec'22) example is PyTorch package that was compromised using dependency confusion vulnerability (no CVE assigned). 

Packj not only audits for CVEs, but also performs deep static+dynamic code analysis as well as metadata checks to detect any "risky" behavior and attributes, such as spawning of shell, use of SSH keys, mismatch of GitHub code vs packaged code (provenance), lack of 2FA, and several more. Such insecure attributes do not qualify as as CVEs, which is why none of the existing tools can flag them. Packj can flag malicious, typo-squatting, abandoned, vulnerable, and other insecure dependencies (weak links) in your software supply chain.

<details>
    <summary><h4>Show long answer</h4></summary>

The current software supply chain threat model **assumes** that the third-party open-source code is benign, and therefore, security vulnerabilities are only tracked for accidental programming bugs (a.k.a. CVEs). As such, all existing open-source vulnerability scanners **ONLY** report publicly known CVEs and address threats from accidental bugs in benign code. 

A typical example of an accidental programming bug is a missing bounds check on user input, which makes the code vulnerable to buffer overflow attacks. Real-world popular examples include Log4J and HeartBleed. Attackers need to develop an exploit to trigger CVEs (e.g., a crafted TCP/IP packet in case of HeartBleed or a numerically high input to cause buffer overflow). CVEs can be fixed by patching or upgrading to a newer version of the library (e.g., newer version of Log4J fixes the CVE). 

The modern software supply chain threat landscape **shifted** after the Solarwinds attack. Bad actors have found new vulnerabilities, but this time in the supply channel, not code. These new vulnerabilities such as dependency confusion, typo-squatting, protestware (sabotaging), account hijacking, and social engineering are being exploited to propagate malware. Thousands of compromised NPM/PyPI/Ruby packages have been reported. 

In contrast to CVEs, malware is deliberately bad (a.k.a. malicious) code. Moreover, malware itself is an exploit and cannot be patched or fixed by upgrading to a newer version. For example, [dependency confusion attack](https://packj.dev/go?next=https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610) was intentionally malicious; it did not exploit any accidental programming bug in the code. Similarly, an author of popular package sabotaging their own code to [protest](https://packj.dev/go?next=https://en.wikipedia.org/wiki/Peacenotwar) against the war is very much intentional and does not exploit any CVEs. Typo-squatting is another attack vector that bad actors use to propagate malware in popular open-source package registries: it exploits [typos and inexperience of devs](https://packj.dev/go?next=https://discuss.python.org/t/improving-risks-and-consequences-against-typosquatting-on-pypi/5090), not accidental programming bugs or CVEs in the code. 

Existing scanners **FAIL** to detect these Solarwinds-like modern software supply-chain attacks from deliberately vulnerable (malicious) code. These tools simply scan the source code for open-source dependencies, compile a list of all dependencies being used, and look each <dependency-NAME, dependency-VERSION> up in a database (e.g., NVD) to report affected package versions (e.g., vulnerable version of Log4J, LibSSL version affected by HeartBleed).

Packj not only audits for CVEs, but also performs deep static+dynamic code analysis as well as metadata checks to detect any "risky" behavior and attributes, such as spawning of shell, use of SSH keys, mismatch of GitHub code vs packaged code (provenance), lack of 2FA, and several more. Such insecure attributes do not qualify as as CVEs, which is why none of the existing tools can flag them. Packj can flag malicious, typo-squatting, abandoned, vulnerable, and other insecure dependencies (weak links) in your software supply chain. Please read more at [Audit README](https://packj.dev/go?next=https://github.com/ossillate-inc/packj/blob/main/packj/audit/README.md#faq)
</details>

# Customization #

Packj can be easily customized (zero noise) to your threat model. Simply add a [.packj.yaml](https://packj.dev/go?next=https://github.com/ossillate-inc/packj/blob/main/.packj.yaml) file in the top dir of your repo/project and reduce alert fatigue by commenting out unwanted attributes.

# Malware found #

We found over 40 and 20 malicious packages on PyPI and Rubygems, respectively using this tool. A number of them been taken down. Refer to an example below:

<details>
    <summary><h4>Show example malware</h4></summary>

    $ python3 main.py audit pypi:krisqian

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
</details>


Packj flagged KrisQian (v0.0.7) as suspicious due to absence of source repo and use of sensitive APIs (network, code generation) during package installation time (in setup.py). We decided to take a deeper look, and found the package malicious. Please find our detailed analysis at [https://packj.dev/malware/krisqian](https://packj.dev/go?next=https://packj.dev/malware/krisqian).

More examples of malware we found are listed at [https://packj.dev/malware](https://packj.dev/go?next=https://packj.dev/malware) Please reach out to us at [oss@ossillate.com](mailto:oss@ossillate.com) for full list.

# Resources #

To learn more about Packj tool or open-source software supply chain attacks, refer to our

[![PyConUS'22 Video](https://img.youtube.com/vi/Rcuqn56uCDk/hqdefault.jpg)](https://packj.dev/go?next=https://www.youtube.com/watch?v=Rcuqn56uCDk)
[![OSSEU'22 Video](https://img.youtube.com/vi/a7BfDGeW_jY/hqdefault.jpg)](https://packj.dev/go?next=https://www.youtube.com/watch?v=a7BfDGeW_jY)

- PyConUS'22 [talk](https://packj.dev/go?next=https://www.youtube.com/watch?v=Rcuqn56uCDk) and [slides](https://packj.dev/go?next=https://speakerdeck.com/ashishbijlani/pyconus22-slides).
- BlackHAT Asia'22 Arsenal [presentation](https://packj.dev/go?next=https://www.blackhat.com/asia-22/arsenal/schedule/#mitigating-open-source-software-supply-chain-attacks-26241)
- PackagingCon'21 [talk](https://packj.dev/go?next=https://www.youtube.com/watch?v=PHfN-NrUCoo) and [slides](https://packj.dev/go?next=https://speakerdeck.com/ashishbijlani/mitigating-open-source-software-supply-chain-attacks)
- BlackHat USA'22 Arsenal talk [Detecting typo-squatting, backdoored, abandoned, and other "risky" open-source packages using Packj](https://www.blackhat.com/us-22/arsenal/schedule/#detecting-typo-squatting-backdoored-abandoned-and-other-risky-open-source-packages-using-packj-28075)
- Academic [dissertation](https://packj.dev/go?next=https://cyfi.ece.gatech.edu/publications/DUAN-DISSERTATION-2019.pdf) on open-source software security and the [paper](https://packj.dev/go?next=https://www.ndss-symposium.org/wp-content/uploads/ndss2021_1B-1_23055_paper.pdf) from our group at Georgia Tech that started this research.
- Open Source Summit, Europe'22 talk [Scoring dependencies to detect “weak links” in your open-source software supply chain](https://packj.dev/go?next=https://osseu2022.sched.com/overview/type/SupplyChainSecurityCon) - presentation video on [YouTube](https://packj.dev/go?next=https://www.youtube.com/watch?v=a7BfDGeW_jY)
- NullCon'22 talk [Unearthing Malicious And Other “Risky” Open-Source Packages Using Packj](https://packj.dev/go?next=https://nullcon.net/goa-2022/unearthing-malicious-and-other-risky-open-source-packages-using-packj)

# Feature roadmap #

* Add support for other language ecosystems. Rust is a work in progress [ETA: Mar '22].
* Add functionality to detect several other "risky" code as well as metadata attributes [ETA: Feb '22].
* Self-hosted Packj webserver and several useful integrations (e.g., Gitlab runner) [ETA: Feb'22].

Watch :eyes: this repo to stay up to date.

Have a feature or support request? Please visit our [GitHub discussion page](https://packj.dev/go?next=https://github.com/ossillate-inc/packj/discussions/) or join our [discord community](https://discord.gg/qFcqaV2wYa) for discussion and requests.

# Team and contributors #

Packj has been developed by Cybersecurity researchers at [Ossillate Inc.](https://packj.dev/go?next=https://packj.dev/team) and external collaborators to help developers mitigate risks of supply chain attacks when sourcing untrusted third-party open-source software dependencies. We thank our developers and collaborators. Show your appreciation by giving us a :star: if you like our work.

We welcome code contributions with open arms. See [CONTRIBUTING.md](CONTRIBUTING.md) guidelines. Found a bug? Please open an issue. Refer to our [SECURITY.md](SECURITY.md) guidelines to report a security issue.

# FAQ #

<details>
	<summary><b>What Package Managers (Registries) are supported?</b></summary>

Packj can currently vet NPM, PyPI, and RubyGems packages for "risky" attributes. We are adding support for Rust.
	
</details>

<details>
	<summary><b>What techniques does Packj employ to detect risky/malicious packages?</b></summary>

Packj uses static code analysis, dynamic tracing, and metadata analysis for comprehensive auditing. Static analysis alone is not sufficient to flag sophisticated malware that can hide itself better using code obfuscation. Dynamic analysis is performed by installing the package under `strace` and monitoring it's runtime behavior. Please read more at [Audit README](https://packj.dev/go?next=https://github.com/ossillate-inc/packj/blob/main/packj/audit/README.md).
	
</details>

<details>
	<summary><b>Does it work on obfuscated calls? For example, a base 64 encrypted string that gets decrypted and then passed to a shell?</b></summary>

This is a very common malicious behavior. Packj detects code obfuscation as well as spawning of shell commands (exec system call). For example, Packj can  flag use of `getattr()` and `eval()` API as they indicate "runtime code generation"; a developer can go and take a deeper look then. See [main.py](https://packj.dev/go?next=https://github.com/ossillate-inc/packj/blob/main/packj/audit/main.py#L512) for details.
	
</details>
