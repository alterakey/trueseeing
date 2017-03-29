import asyncio
import os
import ssl
import tempfile
import websockets
import sys
import logging
import certifi

KEY = None
_YIELD = 0.00000001

async def msg(websocket):
    while True:
        try:
            m = await websocket.recv()
            fd, content = int(m[0]), m[1:]
            if fd == 1:
                sys.stdout.write(content)
            elif fd == 2:
                sys.stderr.write(content)
        except websockets.exceptions.ConnectionClosed as e:
            if e.code == 1000:
                return
            else:
                raise

async def send(websocket, f):
    while True:
        try:
            block = f.read(1024 * 1024)
            if block:
                await websocket.send(block)
                await asyncio.sleep(_YIELD)
            else:
                await websocket.send(b'')
                return
        except websockets.exceptions.ConnectionClosed as e:
            if e.code == 1000:
                return
            else:
                raise

async def complete_either(a, b):
    a_task = asyncio.ensure_future(a)
    b_task = asyncio.ensure_future(b)
    done, pending = await asyncio.wait([a_task, b_task], return_when=asyncio.FIRST_COMPLETED)
    for t in pending:
        t.cancel()
    for t in done:
        _, exc = t.result(), t.exception()
        if exc is not None:
            raise exc

async def hello(mode, host, port, target):
    context = ssl.create_default_context()
    context.load_verify_locations(cafile=certifi.where())
    if KEY is not None:
        key = {'X-Trueseeing2-Key':KEY}
    else:
        key = None

    if mode in ['analyze', 'fingerprint']:
        with open(target, 'rb') as f:
            async with websockets.connect('wss://%s:%d/%s' % (host, port, mode), extra_headers=key, ssl=context) as websocket:
                m = await websocket.recv()
                fd, content = int(m[0]), m[1:]
                if fd == 1:
                    sys.stdout.write(content)
                elif fd == 2:
                    sys.stderr.write(content)
                await complete_either(msg(websocket), send(websocket, f))
                await msg(websocket)

def shell():
    import sys
    import os
    import getopt
    import re
    import configparser

    exploitation_mode = False
    fingerprint_mode = False

    log_level = logging.INFO
    configfile_required = False
    configfile = os.path.join(os.environ['HOME'], '.trueseeing2', 'config')
    connect_to = dict(host='trueseeing.io', port=443)

    opts, targets = getopt.getopt(sys.argv[1:], 'dW:c:p:', ['debug', 'fingerprint', 'exploit-resign', 'exploit-unsign', 'exploit-enable-debug', 'exploit-enable-backup', 'config=', 'port='])
    for o, a in opts:
        if o in ['-c', '--config']:
            configfile = a
            configfile_required = True
        if o in ['--fingerprint']:
            fingerprint_mode = True
        if o in ['--exploit-resign', '--exploit-unsign', '--exploit-enable-debug', '--exploit-enable-backup']:
            exploitation_mode = True
        if o in ['-p', '--port']:
            if ':' in a:
                host, port = a.rsplit(':', maxsplit=1)
                connect_to['host'] = host
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
        KEY = parser['trueseeing']['key']
    except (KeyError, configparser.NoSectionError):
        pass

    if fingerprint_mode:
        asyncio.get_event_loop().run_until_complete(hello('fingerprint', connect_to['host'], connect_to['port'], targets[0]))
    elif exploitation_mode:
        pass
    else:
        asyncio.get_event_loop().run_until_complete(hello('analyze', connect_to['host'], connect_to['port'], targets[0]))

if __name__ == '__main__':
    shell()
