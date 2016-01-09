# Vulnerabilities:
# * Privacy: Tainted data en clair: logs
# * Privacy: IMEI/IMSI on the wire
# * Privacy: Tainted data en clair: the wire
# * Privacy: Tainted data en clair: permissive files
# * Privacy: Tainted data en clair: preferences
# * Privacy: Transmitting tainted data to questionable entity (country)

from trueseeing.context import warning_on

def check_security_dataflow_file(context):
  return [
    warning_on(name='com/gmail/altakey/model/DeviceInfo.java', row=24, col=0, desc='insecure data flow into file: IMEI/IMSI', opt='-Wsecurity-dataflow-file'),
  ]

def check_security_dataflow_wire(context):
  return [
    warning_on(name='com/gmail/altakey/api/ApiClient.java', row=48, col=0, desc='insecure data flow on wire: IMEI/IMSI', opt='-Wsecurity-dataflow-wire'),
  ]
