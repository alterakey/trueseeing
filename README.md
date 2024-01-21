# README

![Last release](https://img.shields.io/github/v/release/alterakey/trueseeing)
![Last release date](https://img.shields.io/github/release-date-pre/alterakey/trueseeing)
![Main branch deploy status](https://github.com/alterakey/trueseeing/workflows/deploy/badge.svg)
![Main branch last commit](https://img.shields.io/github/last-commit/alterakey/trueseeing/main)

trueseeing is a fast, accurate and resillient vulnerabilities scanner for Android apps.  We operate on the Dalvik VM level -- i.e. we don't care if the target app is obfuscated or not.

## Capability

Currently we can:

* Automatically scan app for vulnerabilities, reporting in HTML/JSON/text format (see below)
* Manipulate app for easier analysis: e.g. enabling debug bit, enabling full backup, disabling TLS pinning, manipulating target API level, etc.
* Examine app for general information
* Copy in/out app data through debug interface
* Search for certain calls/consts/sput/iput
* Deduce constants/typesets for args of op
* etc.

## Installation

### Containers

NOTE:
 * As of 2.1.9, we are on ghcr.io. (Docker Hub is somewhat deprecated)
 * Requires adbd in the host to control devices.

We provide containers so you can use right away as follows; now this is also the recommended way, and the only way if you are on Windows, to run:

	$ docker run --rm -v $(pwd):/out -v ts2:/cache ghcr.io/alterakey/trueseeing

If you want to run statelessly you omit mounting volume onto /cache (not recommended for day-to-day use though; also see [#254](https://github.com/alterakey/trueseeing/issues/254)):

	$ docker run --rm -v $(pwd):/out ghcr.io/alterakey/trueseeing


### With pip

Alternatively, you can install it with pip as follows. This might be useful for extensions, as it allows us the greatest freedom. Just remember you need a JRE and Android SDK (optionally; to mess with devices):

	$ pip install --user trueseeing
	$ trueseeing

## Usage

### Interactive mode

With trueseeing you can interactively scan/analyze/patch/etc. apps -- making it the ideal choice for manual analysis:

	$ docker run -it --rm -v $(pwd):/out -v ts2:/cache ghcr.io/alterakey/trueseeing --inspect target.apk
	[+] trueseeing 2.1.9
	ts[target.apk]> ?
	...
	ts[target.apk]> i                      # show generic information
	...
	ts[target.apk]> pf AndroidManifest.xml # show manifest file
	...
	ts[target.apk]> a                      # analyze resources too
	...
	ts[target.apk]> /s something           # search text
	...
	ts[target.apk]> as                     # scan
	...
	[+] done, found 6403 issues (174.94 sec.)
	ts[target.apk]> gh report.html

### Batch mode

We accept an inline command (`-c`) or script file (`-i`) to run before giving you prompt, as well as quitting right away instead of prompting (`-q`; we don't require a tty in this mode!).

You can use the features to conduct a batch scan, as follows e.g. to dump findings right onto the stderr:

	$ docker run --rm -v $(pwd):/out -v ts2:/cache ghcr.io/alterakey/trueseeing -qc 'as' target.apk

To generate a report file in HTML format:

	$ docker run --rm -v $(pwd):/out -v ts2:/cache ghcr.io/alterakey/trueseeing -qc 'as;gh report.html' target.apk

To generate a report file in JSON format:

	$ docker run --rm -v $(pwd):/out -v ts2:/cache ghcr.io/alterakey/trueseeing -qc 'as;gj report.json' target.apk

To get report generated in stdout, omit filename from final `g*` command:

	$ docker run --rm -v $(pwd):/out -v ts2:/cache ghcr.io/alterakey/trueseeing -qc 'as;gh' target.apk > report.html
	$ docker run --rm -v $(pwd):/out -v ts2:/cache ghcr.io/alterakey/trueseeing -qc 'as;gj' target.apk > report.json

### Non-interactive scan mode (deprecated)

Traditionally, you can scan apps with the following command line to get findings listed in stderr:

	$ docker run --rm -v $(pwd):/out -v ts2:/cache ghcr.io/alterakey/trueseeing --scan target.apk

To generate a report in HTML format:

	$ docker run --rm -v $(pwd):/out -v ts2:/cache ghcr.io/alterakey/trueseeing --scan --scan-output report.html target.apk
	$ docker run --rm -v $(pwd):/out -v ts2:/cache ghcr.io/alterakey/trueseeing --scan --scan-report=html --scan-output report.html target.apk

To generate a report in JSON format:

	$ docker run --rm -v $(pwd):/out -v ts2:/cache ghcr.io/alterakey/trueseeing --scan --scan-report=json --scan-output report.json target.apk

To get report generated in stdout, specify '-' as filename:

	$ docker run --rm -v $(pwd):/out -v ts2:/cache ghcr.io/alterakey/trueseeing --scan --scan-output - target.apk > report.html
	$ docker run --rm -v $(pwd):/out -v ts2:/cache ghcr.io/alterakey/trueseeing --scan --scan-report=html --scan-output - target.apk > report.html
	$ docker run --rm -v $(pwd):/out -v ts2:/cache ghcr.io/alterakey/trueseeing --scan --scan-report=json --scan-output - target.apk > report.json

## Advanced Usages

### Extensions

You can write your own signatures etc. as extensions.  Extensions are placed under `/ext` (containers) or `~/.trueseeing2/extensions/` (pip) . We provide type information so you can not only type-check your extensions with `mypy` but also get a decent assist from IDEs.

_TBD: Document extension APIs_


## Build

To build:

	$ git clone https://github.com/alterakey/trueseeing.git wc
	$ docker build -t trueseeing wc

If you are to hack it, please do something like this instead; in essence, install [flit](https://flit.pypa.io/en/stable/) , and have it pull dependencies and toolchains need to validate the code; namely [mypy](https://github.com/python/mypy) and [pflake8](https://github.com/csachs/pyproject-flake8):

	$ git clone https://github.com/alterakey/trueseeing.git wc
	$ cd wc
	$ python3 -m venv .venv
	$ source .venv/bin/activate
	(.venv) $ pip install flit
	(.venv) $ flit install --deps=develop --only-deps
	(.venv) $ (... hack ...)
	(.venv) $ mypy trueseeing && pflake8 trueseeing  # to validate
	Success: no issues found in XX source files
	(.venv) $ docker build -t trueseeing .           # to build

## Details

### Vulnerability Classes

Currently we can detect the following class of vulnerabilities, largely ones covered in OWASP Mobile Top 10 - 2016:

  * Improper Platform Usage (M1)

	* Debuggable
	* Inadvent publishing of Activities, Services, ContentProviders, BroadcastReceivers

  * Insecure Data (M2)

	* Backupable (i.e. suspectible to the backup attack)
	* Insecure file permissions
	* Logging

  * Insecure Commnications (M3)

	* Lack of pinning (i.e. suspictible to the TLS interception attack)
	* Use of cleartext HTTP
	* Tamperable WebViews

  * Insufficient Cryptography (M5)

	* Hardcoded passphrase/secret keys
	* Vernum ciphers with static keys
	* Use of the ECB mode

  * Client Code Quality Issues (M7)

	* Reflectable WebViews (i.e. XSSs in such views should be escalatable to remote code executions via JS reflection)
	* Usage of insecure policy on mixed contents

  * Code Tampering (M8)

	* Hardcoded certificates

  * Reverse Engineering (M9)

	* Lack of obfuscation

### Origin of Project Name?

The D&D spell, [True Seeing](https://www.dandwiki.com/wiki/SRD:True_Seeing).
