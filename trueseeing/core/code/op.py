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
import attr

class Token:
  def __init__(self, t=None, v=None):
    self.t = t
    self.v = v

  def __repr__(self):
    return '<Token t={} v={}>'.format(self.t, self.v)

  def eq(self, t, v):
    return (self.t, self.v) == (t, v)

class Op:
  def __init__(self, t=None, v=None, p=None, id_=None):
    self.t = t
    self.v = v
    self.p = p
    self._id = id_

  def __repr__(self):
    return '<Op t={} v={}, p={}>'.format(self.t, self.v, self.p)

  def eq(self, t, v):
    return (self.t, self.v) == (t, v)

  @staticmethod
  def of_id(id_):
    return Op(None, None, None, id_)