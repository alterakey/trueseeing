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

import itertools
import logging
import pprint

from .code import CodeFlows

log = logging.getLogger(__name__)

class DataFlows:
  class NoSuchValueError(Exception):
    pass

  class RegisterDecodeError(Exception):
    pass

  @staticmethod
  def likely_calling_in(store, ops):
    pass

  @staticmethod
  def into(store, o):
    return DataFlows.analyze(store, o)

  @staticmethod
  def decoded_registers_of(ref, type_=frozenset):
    if ref.t == 'multireg':
      regs = ref.v
      if ' .. ' in regs:
        from_, to_ = regs.split(' .. ')
        return type_(['%s%d' % (from_[0], c) for c in range(int(from_[1:]), int(to_[1:]) + 1)])
      elif ',' in regs:
        return type_([r.strip() for r in regs.split(',')])
      else:
        return type_([regs.strip()])
    elif ref.t == 'reg':
      regs = ref.v
      return type_([regs.strip()])
    else:
      raise DataFlows.RegisterDecodeError("unknown type of reference: %s, %s" % (ref.t, ref.v))

  # TBD: pack as SQL function
  @staticmethod
  def looking_behind_from(store, op):
    focus = None
    for o in store.query().reversed_insns_in_method(op):
      if focus is None:
        if o.t != 'label':
          yield o
        else:
          if not o.v.startswith("try_"):
            focus = o.v
      else:
        if o.t != 'id' or not any(p.v == focus for p in o.p):
          continue
        else:
          focus = None

  @staticmethod
  def solved_constant_data_in_invocation(store, invokation_op, index):
    assert invokation_op.t == 'id' and invokation_op.v.startswith('invoke')
    graph = DataFlows.analyze(store, invokation_op)
    try:
      reg = DataFlows.decoded_registers_of(invokation_op.p[0], type_=list)[index + (0 if ('-static' in invokation_op.v) else 1)]
    except IndexError:
      raise DataFlows.NoSuchValueError('argument not found at index %d' % index)
    arg = graph[invokation_op][reg]
    try:
      if arg.t == 'id' and arg.v.startswith('const'):
        return arg.p[1].v
      else:
        raise DataFlows.NoSuchValueError('not a compile-time constant: %r' % arg)
    except AttributeError:
      raise DataFlows.NoSuchValueError('not a compile-time constant: %r' % arg)

  @staticmethod
  def walk_dict_values(d):
    try:
      for v in d.values():
        yield from DataFlows.walk_dict_values(v)
    except AttributeError:
      yield d

  @staticmethod
  def solved_possible_constant_data_in_invocation(store, invokation_op, index):
    assert invokation_op.t == 'id' and invokation_op.v.startswith('invoke')
    graph = DataFlows.analyze(store, invokation_op)
    reg = DataFlows.decoded_registers_of(invokation_op.p[0], type_=list)[index + (0 if ('-static' in invokation_op.v) else 1)]
    return {x.p[1].v for x in DataFlows.walk_dict_values(graph[invokation_op][reg]) if x is not None and x.t == 'id' and x.v.startswith('const')}

  @staticmethod
  def solved_typeset_in_invocation(store, invokation_op, index):
    assert invokation_op.t == 'id' and invokation_op.v.startswith('invoke')
    graph = DataFlows.analyze(store, invokation_op)
    reg = DataFlows.decoded_registers_of(invokation_op.p[0], type_=list)[index + (0 if ('-static' in invokation_op.v) else 1)]
    arg = graph[invokation_op][reg]
    def assumed_target_type_of_op(x):
      assert x.t == 'id'
      if x.v.startswith('const/4'):
        return 'Ljava/lang/Integer;'
      elif x.v.startswith('const-string'):
        return 'Ljava/lang/String;'
      elif x.v.startswith('new-array'):
        return x.p[2].v
      else:
        return 'Ljava/lang/Object;'
    return {assumed_target_type_of_op(x) for x in DataFlows.walk_dict_values(graph[invokation_op][reg]) if x is not None and x.t == 'id'}

  @staticmethod
  def analyze(store, op, state=None):
    if state is None:
      state = set()
    if op is not None and op.t == 'id':
      if op._id in state:
        return None
      else:
        state.add(op._id)
      if any(op.v.startswith(x) for x in ['const','new-','move-exception']):
        return op
      elif op.v in ['move', 'array-length']:
        return {op:{k:DataFlows.analyze(store, DataFlows.analyze_recent_load_of(store, op, k), state) for k in DataFlows.decoded_registers_of(op.p[1])}}
      elif any(op.v.startswith(x) for x in ['aget-']):
        assert len(op.p) == 3
        return {op:{k:DataFlows.analyze(store, DataFlows.analyze_recent_array_load_of(store, op, k), state) for k in (DataFlows.decoded_registers_of(op.p[1]) | DataFlows.decoded_registers_of(op.p[2]))}}
      elif any(op.v.startswith(x) for x in ['sget-']):
        assert len(op.p) == 2
        return {op:{k:DataFlows.analyze(store, DataFlows.analyze_recent_static_load_of(store, op), state) for k in DataFlows.decoded_registers_of(op.p[0])}}
      elif any(op.v.startswith(x) for x in ['iget-']):
        assert len(op.p) == 3
        return {op:{k:DataFlows.analyze(store, DataFlows.analyze_recent_instance_load_of(store, op), state) for k in DataFlows.decoded_registers_of(op.p[0])}}
      elif op.v.startswith('move-result'):
        return DataFlows.analyze(store, DataFlows.analyze_recent_invocation(store, op), state)
      else:
        try:
          return {op:{k:DataFlows.analyze(store, DataFlows.analyze_recent_load_of(store, op, k), state) for k in DataFlows.decoded_registers_of(op.p[0])}}
        except DataFlows.RegisterDecodeError:
          return None

  @staticmethod
  def analyze_recent_static_load_of(store, op):
    assert op.t == 'id' and any(op.v.startswith(x) for x in ['sget-'])
    target = op.p[1].v
    for o in itertools.chain(DataFlows.looking_behind_from(store, op), store.query().sputs(target)):
      if o.t == 'id' and o.v.startswith('sput-'):
        if o.p[1].v == target:
          return o
    else:
      log.debug("analyze_recent_static_load_of: failed static trace: %r" % op)
      return None

  @staticmethod
  def analyze_load(store, op):
    if op.t == 'id':
      if any(op.v.startswith(x) for x in ['const','new-','move','array-length','aget-','sget-','iget-']):
        return DataFlows.decoded_registers_of(op.p[0])
      elif any(op.v.startswith(x) for x in ['invoke-direct', 'invoke-virtual', 'invoke-interface']):
        # Imply modification of "this"
        return frozenset(DataFlows.decoded_registers_of(op.p[0], type_=list)[:1])
      else:
        return frozenset()

  @staticmethod
  def analyze_recent_load_of(store, from_, reg, stage=0):
    if reg.startswith('p'):
      index = int(reg.replace('p', ''))
      for caller in CodeFlows.callers_of(store, from_):
        if store.query().qualname_of(from_) != store.query().qualname_of(caller):
          caller_reg = DataFlows.decoded_registers_of(caller.p[0], type_=list)[index]
          log.debug("analyze_recent_load_of: retrace: %r [%s] <-> %r [%s] [stage: %d]" % (from_, reg, caller, caller_reg, stage))
          if stage < 5:
            retraced = DataFlows.analyze_recent_load_of(store, caller, caller_reg, stage=stage+1)
            if retraced:
              return retraced
      return None
    for o in DataFlows.looking_behind_from(store, from_):
      if o.t == 'id':
        if reg in DataFlows.analyze_load(store, o):
          return o

  # TBD: tracing on static-array fields
  @staticmethod
  def analyze_recent_array_load_of(store, from_, reg):
    return DataFlows.analyze_recent_load_of(store, from_, reg)

  # TBD: tracing on static-instance fields
  @staticmethod
  def analyze_recent_instance_load_of(store, op):
    assert len(op.p) == 3
    assert op.t == 'id' and any(op.v.startswith(x) for x in ['iget-'])
    field = op.p[2].v
    instance_reg = DataFlows.decoded_registers_of(op.p[1], type_=list)[0]
    for o in itertools.chain(DataFlows.looking_behind_from(store, op), store.query().iputs(field)):
      if o.t == 'id' and o.v.startswith('iput-') and o.p[2].v == field:
        return o

  @staticmethod
  def analyze_recent_invocation(store, from_):
    for o in DataFlows.looking_behind_from(store, from_):
      if o.t == 'id' and o.v.startswith('invoke'):
        return o
