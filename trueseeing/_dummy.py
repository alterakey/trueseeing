"""
This file must be kept in a python2 and python3 compatible syntax.
"""

from __future__ import print_function  # this is here for the version check to work on Python 2.

import sys

if sys.version_info < (3, 0):
    print("#" * 76, file=sys.stderr)
    print("# trueseeing requires Python 3.0 or higher!                                #", file=sys.stderr)
    print("#" * 76, file=sys.stderr)
    sys.exit(1)
else:
    from .shell import *
