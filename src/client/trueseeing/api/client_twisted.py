import sys

from twisted.internet import reactor, threads
from autobahn.twisted.websocket import WebSocketClientProtocol, WebSocketClientFactory, connectWS

KEY = None

class TrueseeingClientProtocol(WebSocketClientProtocol):
    def __init__(self, f):
        super(TrueseeingClientProtocol, self).__init__()
        self._f = f

    def onOpen(self):
        self._state = 0

    @staticmethod
    def write_message(payload):
        fd, content = int(payload[0]), payload[1:]
        if fd == 1:
            sys.stdout.write(content)
        elif fd == 2:
            sys.stderr.write(content)

    def onMessage(self, payload, isBinary):
        if self._state == 0:
            self.write_message(payload)
            self._state = 1
        if self._state == 1:
            def send():
                while True:
                    block = self._f.read(1024 * 1024)
                    if block:
                        self.sendMessage(block, isBinary=True)
                    else:
                        self.sendMessage(b'', isBinary=True)
                        return True
            def sendDone(_):
                self._state = 3
            threads.deferToThread(send).addCallback(sendDone)
            self._state = 2
            return
        if self._state == 2:
            self.write_message(payload)
        if self._state == 3:
            self.write_message(payload)

    def onClose(self, wasClean, code, reason):
        if code != 1000:
            sys.stderr.write("WebSocket connection closed: {0}".format(reason))
        reactor.stop()

    @staticmethod
    def withFile(f):
        return lambda: TrueseeingClientProtocol(f)

def hello(host, port, target):
    from twisted.internet import reactor

    if KEY is not None:
        key = {'X-Trueseeing2-Key':KEY}
    else:
        key = None
    with open(target, 'rb') as f:
        factory = WebSocketClientFactory(u"wss://%s:%d/analyze" % (host, port), headers=key)
        factory.isSecure = True
        factory.protocol = TrueseeingClientProtocol.withFile(f)
        connectWS(factory)
        reactor.run()

def shell():
    import sys
    import os
    import getopt
    import re
    try:
        import ConfigParser as configparser
    except ImportError:
        import configparser

    configfile_required = False
    configfile = os.path.join(os.environ['HOME'], '.trueseeing2', 'config')
    connect_to = dict(host='trueseeing.io', port=443)

    opts, targets = getopt.getopt(sys.argv[1:], 'dc:p:', ['debug', 'config=', 'port='])
    for o, a in opts:
        if o in ['-d', '--debug']:
            pass
        if o in ['-c', '--config']:
            configfile = a
            configfile_required = True
        if o in ['-p', '--port']:
            if ':' in a:
                host, port = a.rsplit(':', maxsplit=1)
                connect_to['host'] = host,
                connect_to['port'] = int(port)
            else:
                connect_to['port'] = int(a)

    if len(targets) != 1:
        sys.stderr.write("%(me)s: usage: %(me)s <apk>\n" % dict(me=sys.argv[0]))
        sys.exit(2)

    if configfile_required and not os.path.exists(configfile):
        sys.stderr.write('%s: config file is not found\n', sys.argv[0])
        sys.exit(1)

    try:
        global KEY
        parser = configparser.ConfigParser()
        parser.read(configfile)
        KEY = parser.get('trueseeing', 'key')
    except (KeyError, configparser.NoSectionError):
        pass

    hello(connect_to['host'], connect_to['port'], targets[0])

if __name__ == '__main__':
    shell()
