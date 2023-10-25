# README

trueseeing is a fast, accurate and resillient vulnerabilities scanner for Android apps.  It operates on Android Packaging File (APK) and outputs a comprehensive report in HTML, JSON or a CI-friendly format.  It doesn't matter if the APK is obfuscated or not.

## Capability

Currently trueseeing can detect the following class of vulnerabilities:

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

## Installation

We provide containers so you can use right away as follows; now this is also the recommended way to run:

	$ docker run --rm -v $(pwd):/out -v ts2:/cache alterakey/trueseeing

If you want to run statelessly you omit mounting volume onto /cache (not recommended for day-to-day use though):

	$ docker run --rm -v $(pwd):/out alterakey/trueseeing

Finally if you would like to use plain old installation (e.g. for interacting with devices), you can do as follows:

	$ pip3 install trueseeing

## Usage

The following command line is sufficient to scan a APK (target.apk), yielding findings listed in stderr:

	$ docker run --rm -v $(pwd):/out -v ts2:/cache alterakey/trueseeing target.apk

To generate a report in HTML format:

	$ docker run --rm -v $(pwd):/out -v ts2:/cache alterakey/trueseeing -o report.html target.apk
	$ docker run --rm -v $(pwd):/out -v ts2:/cache alterakey/trueseeing --format=html -o report.html target.apk

To generate a report in JSON format:

	$ docker run --rm -v $(pwd):/out -v ts2:/cache alterakey/trueseeing --format=json -o report.json target.apk

To get report generated in stdout, specify '-' as filename:

	$ docker run --rm -v $(pwd):/out -v ts2:/cache alterakey/trueseeing -o - target.apk > report.html
	$ docker run --rm -v $(pwd):/out -v ts2:/cache alterakey/trueseeing --format=html -o - target.apk > report.html
	$ docker run --rm -v $(pwd):/out -v ts2:/cache alterakey/trueseeing --format=json -o - target.apk > report.json

To fix (not all) problems it catches:

	$ docker run --rm -v $(pwd):/out -v ts2:/cache alterakey/trueseeing --patch-all target.apk

From 2.1.8, we have rewritten the means of interactively analyzing apps; inspect mode II (hence, forget that I). You can try it as follows:

	$ docker run -it --rm -v $(pwd):/out -v ts2:/cache alterakey/trueseeing --inspect target.apk
	[+] trueseeing 2.1.8 [inspect mode]
	ts[target.apk]> ?
	...
	ts[target.apk]> aa
	...
	[+] done, found 6403 issues (174.94 sec.)
	ts[target.apk]> i
	...
	ts[target.apk]> gh report.html
