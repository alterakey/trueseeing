# README

![Last release](https://img.shields.io/github/v/release/alterakey/trueseeing)
![Last release date](https://img.shields.io/github/release-date-pre/alterakey/trueseeing)
![Main branch deploy status](https://github.com/alterakey/trueseeing/workflows/deploy/badge.svg)
![Main branch last commit](https://img.shields.io/github/last-commit/alterakey/trueseeing/main)

trueseeing is a fast, accurate and resillient vulnerability scanner for Android apps.  We operate on the Dalvik VM level -- i.e. we don't care if the target app is obfuscated or not.

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

Alternatively, you can install our package with pip as follows. This form of installation might be useful for extensions, as it grants them the greatest freedom. Just remember you need a JRE and Android SDK (optionally; to mess with devices):

	$ pip install --user trueseeing
	$ trueseeing

## Usage

### Interactive mode

You can interactively scan/analyze/patch/etc. apps -- making it the ideal choice for manual analysis:

	$ trueseeing --inspect target.apk
	warning: --inspect is deprecated; ignored as default
	[+] trueseeing 2.2.0
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

	$ trueseeing -eqc 'as' target.apk

To generate a report file in HTML format:

	$ trueseeing -eqc 'as;gh report.html' target.apk

To generate a report file in JSON format:

	$ trueseeing -eqc 'as;gj report.json' target.apk

To get report generated in stdout, omit filename from final `g*` command:

	$ trueseeing -eqc 'as;gh' target.apk > report.html
	$ trueseeing -eqc 'as;gj' target.apk > report.json

### Non-interactive scan mode (deprecated)

Traditionally, you can scan apps with the following command line to get findings listed in stderr:

	$ trueseeing --scan target.apk

To generate a report in HTML format:

	$ trueseeing --scan --scan-output report.html target.apk
	$ trueseeing --scan --scan-report=html --scan-output report.html target.apk

To generate a report in JSON format:

	$ trueseeing --scan --scan-report=json --scan-output report.json target.apk

To get report generated in stdout, specify '-' as filename:

	$ trueseeing --scan --scan-output - target.apk > report.html
	$ trueseeing --scan --scan-report=html --scan-output - target.apk > report.html
	$ trueseeing --scan --scan-report=json --scan-output - target.apk > report.json

## Advanced Usages

### Extensions

You can write your own commands and signatures as extensions.  Extensions are placed under `/ext` (containers) or `~/.trueseeing2/extensions/` (pip) . Alternatively you can distribute your extensions as wheels. We provide type information so you can not only type-check your extensions with [mypy](https://github.com/python/mypy) but also get a decent assist from IDEs. See the details section for details.

## Build

You can build it as follows:

	$ docker build -t trueseeing https://github.com/alterakey/trueseeing.git#main

To build wheels you can do with [flit](https://flit.pypa.io/en/stable/), as follows:

	$ flit build

To hack it, you need to create a proper build environment. To create one, set up a venv, install [flit](https://flit.pypa.io/en/stable/) in there, and have it pull dependencies and validating toolchains; esp. [mypy](https://github.com/python/mypy) and [pflake8](https://github.com/csachs/pyproject-flake8).  In short, do something like this:

	$ git clone https://github.com/alterakey/trueseeing.git wc
	$ python3 -m venv wc/.venv
	$ source wc/.venv/bin/activate
	(.venv) $ pip install flit
	(.venv) $ flit install --deps=develop -s
	(.venv) $ (... hack ...)
	(.venv) $ trueseeing ...                         # to run
	(.venv) $ mypy trueseeing && pflake8 trueseeing  # to validate
	Success: no issues found in XX source files
	(.venv) $ flit build                             # to build (wheel)
	(.venv) $ docker build -t trueseeing .           # to build (container)


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

### Extension API

Our extension API lays under the `trueseeing.api` package. As we provide type information with it, your IDE will assist you when writing your extensions.

#### Commands

To define new commands, implement `trueseeing.api.Command` and advertise them.

The following class will provide a sample command as `t`, for example:

```python
from typing import TYPE_CHECKING
from trueseeing.api import Command
from truseeing.core.ui import ui
if TYPE_CHECKING:
  from trueseeing.api import CommandMap, CommandPatternMap, ModifierMap, OptionMap, ConfigMap

class MyCommand(Command):
  @staticmethod
  def create() -> Command:
	return MyCommand()

  def get_commands(self) -> CommandMap:
	return {'t':dict(e=self._test, n='t', d='sample command')}

  def get_command_patterns(self) -> CommandPatternMap:
	return dict()

  def get_modifiers(self) -> ModifierMap:
	 return dict()

  def get_options(self) -> OptionMap:
	return dict()

  def get_configs(self) -> ConfigMap:
	return dict()

  async def _test(self) -> None:
	ui.info('hello world')
```

#### Signatures

To define new signatures, implement `trueseeing.api.Signature` and advertise them.

The following class will provide a sample detector as `my-sig`, for example:

```python
from typing import TYPE_CHECKING
from trueseeing.api import Signature
if TYPE_CHECKING:
  from trueseeing.api import SignatureMap, ConfigMap

class MySignature(Signature):
  @staticmethod
  def create() -> Signature:
	return MySignature()

  def get_sigs(self) -> SignatureMap:
	return {'my-sig':dict(e=self._detect, d='sample signature')}

  def get_configs(self) -> ConfigMap:
	return dict()

  async def _detect(self) -> None:
	self._helper.raise_issue(
	  self._helper.build_issue(
		sigid='my-sig',
		title='hello world',
		cvss='CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/',
	  )
	)
```


#### File Formats

To define new file formats, implement `trueseeing.api.FileFormatHandler` and advertise them.

The following class will provide APK file support, for example:

```python
from typing import TYPE_CHECKING
from trueseeing.api import FileFormatHandler
if TYPE_CHECKING:
  from typing import Optional
  from trueseeing.api import FormatMap, ConfigMap
  from trueseeing.core.comtext import Context

class APKFileFormatHandler(FileFormatHandler):
  @staticmethod
  def create() -> FileFormatHandler:
	return APKFileFormatHandler()

  def get_formats(self) -> FormatMap:
	return {r'\.apk$':dict(e=self._handle, d='apk')}

  def get_configs(self) -> ConfigMap:
	return dict()

  def _handle(self, path: str) -> Optional[Context]:
	from trueseeing.core.android.context import APKContext
	return APKContext(path, [])
```

Then make sure you check for context type from your signatures, making them ignored on unsupported contexts:

```python
context = self._helper.get_context('apk')
```

#### Package requirements

Extensions can be either: a) any package placed under `/ext` (container) or `~/.truseeing2/extensions` (pip), or b) any installed module named with the prefix of `trueseeing_ext0_`.

### Origin of Project Name?

The D&D spell, [True Seeing](https://www.dandwiki.com/wiki/SRD:True_Seeing).
