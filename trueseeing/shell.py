import getopt

def processed():
  return [
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

def shell(argv):
  try:
    opts, files = getopt.Getopt(argv[1:], 'f', [])
    for o, a in opts:
      pass
    for e in processed(files):
      print(e)
      return 1
    else:
      return 0
  except :
    print("%s: no input files" % argv[0])
    return 2

def entry():
  import sys
  return shell(sys.argv)
