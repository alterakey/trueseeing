import asyncio
import ssl
import websockets
import base64
import os
from Crypto.Cipher import AES
import hmac
import hashlib
import json
import logging

log = logging.getLogger(__name__)

class TS2Key:
    PERSONALITY = None
    def __init__(self, key):
        self.key = base64.b64decode(key)

    @staticmethod
    def padded(x, boundary=16):
        mod = (boundary - (len(x) % boundary)) % boundary
        return x + (bytes([mod]) * mod)

    @staticmethod
    def unpadded(x, boundary=16):
        mod = x[-1]
        if mod < boundary and x[-mod:] == (bytes([mod])*mod):
            return x[:-mod]
        else:
            return x

    def read(self):
        iv, ciphertext, hash_ = self.key[:16], self.key[16:-32], self.key[-32:]
        if hmac.HMAC(msg=(iv + ciphertext), key=self.PERSONALITY[32:], digestmod=hashlib.sha256).digest() != hash_:
            raise ValueError('invalid token')
        plaintext = TS2Key.unpadded(AES.new(key=self.PERSONALITY[:32], IV=iv, mode=AES.MODE_CBC).decrypt(ciphertext))
        return json.loads(plaintext.decode())

    @classmethod
    def write(cls, cpulimit=None, readlimit=None, expires=None):
        plaintext = json.dumps(dict(cpu=cpulimit, read=readlimit, expires=expires)).encode()
        iv = os.urandom(16)
        ciphertext = AES.new(key=cls.PERSONALITY[:32], IV=iv, mode=AES.MODE_CBC).encrypt(TS2Key.padded(plaintext))
        hash_ = hmac.HMAC(msg=(iv + ciphertext), key=cls.PERSONALITY[32:], digestmod=hashlib.sha256).digest()
        return base64.b64encode(iv + ciphertext + hash_)

class TS2Protocol(asyncio.SubprocessProtocol):
    def __init__(self, loop, ws):
        self.loop = loop
        self.future = asyncio.Future(loop=loop)
        self.ws = ws

    @staticmethod
    async def _send(transport, ws):
        total = 0
        stdin = transport.get_pipe_transport(0)
        while True:
            block = await ws.recv()
            if block:
                stdin.write(block)
                total = total + len(block)
                await ws.send('\rread: %d bytes' % total)
            else:
                stdin.write_eof()
                await ws.send('\rread: %d bytes\n' % total)
                break

    def connection_made(self, transport):
        self.loop.create_task(self._send(transport, self.ws))

    def pipe_data_received(self, fd, data):
        self.loop.create_task(self.ws.send(data.decode('utf-8')))

    def process_exited(self):
        self.future.set_result(True)

async def entry(websocket, path):
    if path == '/analyze':
        loop = asyncio.get_event_loop()
        limits = dict(cpu=240, read=32*1048576, expires=None)
        if 'X-Trueseeing2-Key' in websocket.request_headers:
            try:
                limits.update(TS2Key(websocket.request_headers['X-Trueseeing2-Key']).read())
            except ValueError:
                await websocket.send('API key is invalid\n')
                return

        cmdline = [('--rlimit-%s=%s' % (dict(cpu='cpu', read='input', expires='expires')[k], v)) for k,v in limits.items() if v is not None]
        try:
            transport, protocol = await loop.subprocess_shell(lambda: TS2Protocol(loop, websocket), '/Users/taky/ve/ts2/bin/trueseeing --api%s' % ((' ' + ' '.join(cmdline)) if cmdline else ''))
            await protocol.future
        finally:
            transport.close()

def shell():
    import sys
    import os
    import getopt
    import re
    import configparser

    log_level = logging.INFO
    foreground = False
    configfile_required = False
    configfile = os.path.join('', 'etc', 'trueseeing2', 'trueseeingd_config')
    listen_at = dict(host='::', port=8789)

    opts, _ = getopt.getopt(sys.argv[1:], 'dfc:p:', ['debug', 'foreground', 'config=', 'port='])
    for o, a in opts:
        if o in ['-d', '--debug']:
            debug = logging.DEBUG
            foreground = True
        if o in ['-f', '--foreground']:
            foreground = True
        if o in ['-c', '--config']:
            configfile = a
            configfile_required = True
        if o in ['-p', '--port']:
            if ':' in a:
                host, port = a.rsplit(':', maxsplit=1)
                listen_at['host'] = host,
                listen_at['port'] = int(port)
            else:
                listen_at['port'] = int(a)

    if configfile_required and not os.path.exists(configfile):
        sys.stderr.write('%s: config file is not found\n', sys.argv[0])
        sys.exit(1)

    parser = configparser.ConfigParser()
    parser.read(configfile)
    TS2Key.PERSONALITY = base64.b64decode(parser['trueseeingd']['personality'])

    logging.basicConfig(level=log_level, format="%(msg)s")

    if not foreground:
        if os.fork():
            sys.exit(0)
        else:
            devnull = os.open(os.devnull, os.O_RDWR)
            os.dup2(devnull, 0)
            os.dup2(devnull, 1)
            os.dup2(devnull, 2)

    start_server = websockets.serve(entry, listen_at['host'], listen_at['port'])
    asyncio.get_event_loop().run_until_complete(start_server)
    asyncio.get_event_loop().run_forever()

if __name__ == '__main__':
    shell()
