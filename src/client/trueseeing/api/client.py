import asyncio
import os
import ssl
import tempfile
import websockets
import sys
import logging

KEY = None
_YIELD = 0.00000001

async def msg(websocket):
    while True:
        try:
            sys.stderr.write(await websocket.recv())
        except websockets.exceptions.ConnectionClosed as e:
            if e.code == 1000:
                return
            else:
                raise

async def send(websocket):
    while True:
        try:
            block = sys.stdin.buffer.read(1024 * 1024)
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

async def hello(host, port):
    if KEY is not None:
        key = {'X-Trueseeing2-Key':KEY}
    else:
        key = None
    async with websockets.connect('ws://%s:%d/analyze' % (host, port), extra_headers=key) as websocket:
        sys.stderr.write(await websocket.recv())
        await complete_either(msg(websocket), send(websocket))
        await msg(websocket)

def shell():
    import sys
    import os
    import getopt
    import re
    import configparser

    log_level = logging.INFO
    configfile_required = False
    configfile = os.path.join(os.environ['HOME'], '.trueseeing2', 'config')
    connect_to = dict(host='trueseeing.io', port=443)

    opts, _ = getopt.getopt(sys.argv[1:], 'dc:p:', ['debug', 'config=', 'port='])
    for o, a in opts:
        if o in ['-d', '--debug']:
            debug = logging.DEBUG
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

    if configfile_required and not os.path.exists(configfile):
        sys.stderr.write('%s: config file is not found\n', sys.argv[0])
        sys.exit(1)

    try:
        parser = configparser.ConfigParser()
        parser.read(configfile)
        KEY = parser['trueseeing']['key']
    except KeyError:
        pass

    asyncio.get_event_loop().run_until_complete(hello(connect_to['host'], connect_to['port']))

if __name__ == '__main__':
    shell()
