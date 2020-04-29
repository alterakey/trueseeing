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

    $ pip3 install trueseeing

## Usage

The following command line is sufficient to scan a APK (target.apk):

    $ trueseeing /path/to/target.apk > report.html

To get a JSON format:

    $ trueseeing --output=json /path/to/target.apk  > report.json

To get output in more CI-friendly format:

    $ trueseeing --output=gcc /path/to/target.apk

To fix (not all) problems it catches:

    $ trueseeing --patch-all /path/to/target.apk
