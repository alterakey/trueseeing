import sys

def entry():
  errors = [
	'AndroidManifest.xml:1:0: warning: open permissions: android.permission.READ_PHONE_STATE [-Wmanifest-open-permission]',
	'AndroidManifest.xml:1:0: warning: open permissions: android.permission.READ_SMS [-Wmanifest-open-permission]',
	'AndroidManifest.xml:1:0: warning: missing permissions: android.permission.READ_CONTACTS [-Wmanifest-open-permission]',
	'AndroidManifest.xml:1:0: warning: manipulatable Activity: XXXXXXXActivity [-Wmanifest-manip-activity]',
	'AndroidManifest.xml:1:0: warning: manipulatable BroadcastReceiver: XXXXXXXReceiver [-Wmanifest-manip-broadcastreceiver]',
	'com/gmail/altakey/crypto/Tools.java:5:0: warning: insecure cryptography: static keys: XXXXXX: "XXXXXXXXXXXXXXXXXXXXXXXX" [-Wcrypto-static-keys]',
	'com/gmail/altakey/crypto/Tools.java:6:0: warning: insecure cryptography: static keys: XXXXXX: "XXXXXXXXXXXXXXXXXXXXXXXX" [-Wcrypto-static-keys]',
	'com/gmail/altakey/ui/WebActivity.java:40:0: warning: arbitrary WebView content overwrite [-Wsecurity-arbitrary-webview-overwrite]',
	'com/gmail/altakey/model/DeviceInfo.java:24:0: warning: insecure data flow into file: IMEI/IMSI [-Wsecurity-dataflow-file]',
	'com/gmail/altakey/api/ApiClient.java:48:0: warning: insecure data flow on wire: IMEI/IMSI [-Wsecurity-dataflow-wire]',
]

  if len(sys.argv) > 1:
    for e in errors:
      print(e)
  else:
    print("%s: no input files" % sys.argv[0])
