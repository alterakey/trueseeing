import datetime
import getopt
import sys
import os
import configparser
from api import TS2Key

def shell():
    configfile_required = False
    configfile = os.path.join('', 'etc', 'trueseeing2', 'trueseeingd_config')

    cpulimit = None
    readlimit = None
    expires = None
    try:
        opts, files = getopt.getopt(sys.argv[1:], 'cief:', ['cpu=', 'input=', 'expires=', 'config='])
        for o, a in opts:
            if o in ['-c', '--cpu']:
                cpulimit = int(a)
            if o in ['-i', '--input']:
                readlimit = int(a)
            if o in ['-e', '--expires']:
                expires = int(datetime.datetime.strptime(a, '%Y-%m-%d').timestamp())
            if o in ['-f', '--config']:
                configfile = a
                configfile_required = True
    except IndexError:
        pass

    if configfile_required and not os.path.exists(configfile):
        sys.stderr.write('%s: config file is not found\n', sys.argv[0])
        sys.exit(1)

    parser = configparser.ConfigParser()
    parser.read(configfile)
    TS2Key.KEY1 = parser['trueseeingd']['key1']
    TS2Key.KEY2 = parser['trueseeingd']['key2']

    print('Key is: "%s"' % TS2Key.write(cpulimit=cpulimit, readlimit=readlimit, expires=expires).decode())

if __name__ == '__main__':
    shell()
