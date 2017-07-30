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

import os.path
import pkg_resources

class Store:
  def __init__(self, c):
    self.c = c

  def stage0(self):
    with open(pkg_resources.resource_filename(__name__, os.path.join('libs', 'store.s.sql')), 'r', encoding='utf-8') as f:
      self.c.executescript(f.read())

  def stage1(self):
    with open(pkg_resources.resource_filename(__name__, os.path.join('libs', 'store.0.sql')), 'r', encoding='utf-8') as f:
      self.c.executescript(f.read())

  def stage2(self):
    with open(pkg_resources.resource_filename(__name__, os.path.join('libs', 'store.1.sql')), 'r', encoding='utf-8') as f:
      self.c.executescript(f.read())
