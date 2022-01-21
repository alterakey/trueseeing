# -*- coding: utf-8 -*-
# Trueseeing: Non-decompiling Android application vulnerability scanner
# Copyright (C) 2017-22 Takahiro Yoshimura <altakey@gmail.com>
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

def invoke() -> None:
  import sys
  if sys.version_info < (3, 7):
    print("fatal: requires Python 3.7 or later", file=sys.stderr)
    sys.exit(2)
  else:
    import trueseeing.app.shell
    trueseeing.app.shell.Shell().invoke()
