# -*- coding: utf-8 -*-
# Trueseeing: Non-decompiling Android application vulnerability scanner
# Copyright (C) 2017 Takahiro Yoshimura <takahiro_y@monolithworks.co.jp>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""
This file must be kept in a python2 and python3 compatible syntax.
"""

from __future__ import print_function  # this is here for the version check to work on Python 2.

import sys

def invoke():
  if sys.version_info < (3, 0):
      print("#" * 76, file=sys.stderr)
      print("# trueseeing requires Python 3.0 or higher!                                #", file=sys.stderr)
      print("#" * 76, file=sys.stderr)
      sys.exit(1)
  else:
    import trueseeing.app.shell
    trueseeing.app.shell.Shell().invoke()
