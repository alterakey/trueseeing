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

import re
import collections
import itertools

import pprint
import traceback
from .model import *
from trueseeing.store import Store

import logging
import time
import sys

log = logging.getLogger(__name__)

class SmaliAnalyzer:
  def __init__(self, store):
    self.store = store

  def __enter__(self):
    return self

  def __exit__(self, exc_type, exc_value, traceback):
    pass

  def analyze(self, fs):
    analyzed_ops = 0
    analyzed_methods = 0
    analyzed_classes = 0
    started = time.time()

    for f in fs:
      reg1 = None
      reg2 = None

      for t in P.parsed_flat(f.read()):
        self.store.op_append(t)
        analyzed_ops = analyzed_ops + 1
        if analyzed_ops & 0xffff == 0:
          sys.stderr.write("\ranalyzed: %d ops, %d methods, %d classes (%.02f ops/s)" % (analyzed_ops, analyzed_methods, analyzed_classes, analyzed_ops / (time.time() - started)))
          sys.stderr.flush()

        if reg1 is not None:
          reg1.append(t)
        if reg2 is not None:
          reg2.append(t)

        if t.t == 'directive' and t.v == 'class':
          if reg1 is not None:
            reg1.pop()
            self.store.op_mark_class(reg1, reg1[0])
            reg1 = [t]
            analyzed_classes = analyzed_classes + 1
          else:
            reg1 = [t]
        elif t.t == 'directive' and t.v == 'method':
          if reg2 is None:
            reg2 = [t]
        elif t.t == 'directive' and t.v == 'end' and t.p[0].v == 'method':
          if reg2 is not None:
            self.store.op_mark_method(reg2, reg2[0])
            reg2 = None
            analyzed_methods = analyzed_methods + 1
      else:
        if reg1 is not None:
          self.store.op_mark_class(reg1, reg1[0], ignore_dupes=True)
          reg1 = None
          analyzed_classes = analyzed_classes + 1

    sys.stderr.write(("\ranalyzed: %d ops, %d methods, %d classes" + (" " * 20) + "\n") % (analyzed_ops, analyzed_methods, analyzed_classes))
    sys.stderr.write("analyzed: finalizing\n")
    sys.stderr.flush()
    self.store.op_finalize()
    sys.stderr.write("analyzed: done (%.02f sec)\n" % (time.time() - started))
    sys.stderr.flush()

class P:
  @staticmethod
  def head_and_tail(xs):
    try:
      return xs[0], xs[1:]
    except IndexError:
      return xs[0], None

  @staticmethod
  def parsed_flat(s):
    q = collections.deque(re.split(r'\n+', s))
    while q:
      l = q.popleft()
      if l:
        t = P.parsed_as_op(l)
        if t.t == 'directive' and t.v == 'annotation':
          yield Annotation(t.v, t.p, P.parsed_as_annotation_content(q))
        else:
          yield t

  @staticmethod
  def parsed_as_op(l):
    x, xs = P.head_and_tail(list(P.lexed_as_smali(l)))
    return Op(x.t, x.v, xs)

  @staticmethod
  def parsed_as_annotation_content(q):
    content = Program()
    try:
      while '.end annotation' not in q[0]:
        content.append(q.popleft())
    except IndexError:
      pass
    return content

  @staticmethod
  def lexed_as_smali(l):
    for m in re.finditer(r':(?P<label>[a-z0-9_-]+)|{\s*(?P<multilabel>(?::[a-z0-9_-]+(?: .. )*)+\s*)}|\.(?P<directive>[a-z0-9_-]+)|"(?P<string>.*)"|(?P<reg>[vp][0-9]+)|{(?P<multireg>[vp0-9,. ]+)}|(?P<id>[a-z][a-z/-]*[a-z0-9/-]*)|(?P<reflike>[A-Za-z_0-9/;$()<>\[-]+(?::[A-Za-z_0-9/;$()<>\[-]+)?)|#(?P<comment>.*)', l):
      key = m.lastgroup
      value = m.group(key)
      yield Token(key, value)
