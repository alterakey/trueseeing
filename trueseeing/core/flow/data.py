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

from __future__ import annotations
from typing import TYPE_CHECKING

import itertools

from trueseeing.core.flow.code import CodeFlows
from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import List, Any, Iterable, Mapping, Set, Optional, FrozenSet, Union, Dict
  from typing_extensions import Final
  from trueseeing.core.store import Store
  from trueseeing.core.code.model import Op

  DataGraph = Union[Op, Mapping[Op, Any]]

class DataFlows:
  _stash: Final[Dict[int, str]] = dict()

  class NoSuchValueError(Exception):
    pass

  class RegisterDecodeError(Exception):
    pass

  @classmethod
  def likely_calling_in(cls, store: Store, ops: List[Op]) -> None:
    pass

  @classmethod
  def into(cls, store: Store, o: Op) -> Optional[Union[Op, Mapping[Op, Any]]]:
    return cls.analyze(store, o)

  @classmethod
  def _decoded_registers_of(cls, ref: Op, type_: Any = frozenset) -> Any:
    if ref.t == 'multireg':
      regs = ref.v
      if ' .. ' in regs:
        from_, to_ = regs.split(' .. ')
        return type_([f'{from_[0]}{c:d}' for c in range(int(from_[1:]), int(to_[1:]) + 1)])
      elif ',' in regs:
        return type_([r.strip() for r in regs.split(',')])
      else:
        return type_([regs.strip()])
    elif ref.t == 'reg':
      regs = ref.v
      return type_([regs.strip()])
    else:
      raise cls.RegisterDecodeError(f"unknown type of reference: {ref.t}, {ref.v}")

  @classmethod
  def decoded_registers_of_list(cls, ref: Op) -> List[str]:
    o: List[str] = cls._decoded_registers_of(ref, list)
    return o

  @classmethod
  def decoded_registers_of_set(cls, ref: Op) -> FrozenSet[str]:
    o: FrozenSet[str] = cls._decoded_registers_of(ref, frozenset)
    return o

  # TBD: pack as SQL function
  @classmethod
  def looking_behind_from(cls, store: Store, op: Op) -> Iterable[Op]:
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

  @classmethod
  def solved_constant_data_in_invocation(cls, store: Store, invokation_op: Op, index: int) -> str:
    assert invokation_op.t == 'id' and invokation_op.v.startswith('invoke')
    graph = cls.analyze(store, invokation_op)
    try:
      reg = cls.decoded_registers_of_list(invokation_op.p[0])[index + (0 if ('-static' in invokation_op.v) else 1)]
    except IndexError:
      raise cls.NoSuchValueError(f'argument not found at index {index}')
    if graph:
      try:
        arg = graph[invokation_op][reg] # type: ignore[index]
        if arg.t == 'id' and arg.v.startswith('const'):
          return arg.p[1].v # type: ignore[no-any-return]
        else:
          raise cls.NoSuchValueError(f'not a compile-time constant: {arg!r}')
      except (KeyError, AttributeError):
        raise cls.NoSuchValueError(f'not a compile-time constant: {arg!r}')
    else:
      raise cls.NoSuchValueError(f'not a compile-time constant: {arg!r}')

  @classmethod
  def walk_dict_values(cls, d: DataGraph) -> Iterable[Optional[Op]]:
    try:
      for v in d.values(): # type: ignore[union-attr]
        yield from cls.walk_dict_values(v)
    except AttributeError:
      yield d # type:ignore[misc]

  @classmethod
  def solved_possible_constant_data_in_invocation(cls, store: Store, invokation_op: Op, index: int) -> Set[str]:
    assert invokation_op.t == 'id' and invokation_op.v.startswith('invoke')
    graph = cls.analyze(store, invokation_op)
    reg = cls.decoded_registers_of_list(invokation_op.p[0])[index + (0 if ('-static' in invokation_op.v) else 1)]
    if graph:
      n = graph[invokation_op][reg] # type: ignore[index]
      return {x.p[1].v for x in cls.walk_dict_values(n) if x is not None and x.t == 'id' and x.v.startswith('const')}
    else:
      return set()

  @classmethod
  def solved_typeset_in_invocation(cls, store: Store, invokation_op: Op, index: int) -> Set[Any]:
    assert invokation_op.t == 'id' and invokation_op.v.startswith('invoke')
    graph = cls.analyze(store, invokation_op)
    reg = cls.decoded_registers_of_list(invokation_op.p[0])[index + (0 if ('-static' in invokation_op.v) else 1)]
    if graph:
      arg = graph[invokation_op][reg] # type: ignore[index]

      def assumed_target_type_of_op(x: Op) -> str:
        assert x.t == 'id'
        if x.v.startswith('const/4'):
          return 'Ljava/lang/Integer;'
        elif x.v.startswith('const-string'):
          return 'Ljava/lang/String;'
        elif x.v.startswith('new-array'):
          return x.p[2].v
        else:
          return 'Ljava/lang/Object;'
      return {assumed_target_type_of_op(x) for x in cls.walk_dict_values(arg) if x is not None and x.t == 'id'}
    else:
      return set()

  @classmethod
  def analyze(cls, store: Store, op: Optional[Op], state:Optional[Dict[Optional[int], Optional[DataGraph]]]=None, stage:int = 0) -> Optional[DataGraph]:
    if op is None or stage > 64: # XXX: Is it sufficient? Might be better if we make it tunable?
      return None
    if state is None:
      state = dict()

    o: Optional[DataGraph] = None

    if op.t == 'id':
      if op._id in state:
        return state[op._id]
      if any(op.v.startswith(x) for x in ['const','new-','move-exception']):
        o = op
        state[op._id] = o
        return o
      elif op.v in ['move', 'array-length']:
        o = {op:{k:cls.analyze(store, cls.analyze_recent_load_of(store, op, k), state, stage=stage+1) for k in cls.decoded_registers_of_set(op.p[1])}}
        state[op._id] = o
        return o
      elif any(op.v.startswith(x) for x in ['aget-']):
        assert len(op.p) == 3
        o = {op:{k:cls.analyze(store, cls.analyze_recent_array_load_of(store, op, k), state, stage=stage+1) for k in (cls.decoded_registers_of_set(op.p[1]) | cls.decoded_registers_of_set(op.p[2]))}}
        state[op._id] = o
        return o
      elif any(op.v.startswith(x) for x in ['sget-']):
        assert len(op.p) == 2
        o = {op:{k:cls.analyze(store, cls.analyze_recent_static_load_of(store, op), state, stage=stage+1) for k in cls.decoded_registers_of_set(op.p[0])}}
        state[op._id] = o
        return o
      elif any(op.v.startswith(x) for x in ['iget-']):
        assert len(op.p) == 3
        o = {op:{k:cls.analyze(store, cls.analyze_recent_instance_load_of(store, op), state, stage=stage+1) for k in cls.decoded_registers_of_set(op.p[0])}}
        state[op._id] = o
        return o
      elif op.v.startswith('move-result'):
        o = cls.analyze(store, cls.analyze_recent_invocation(store, op), state, stage=stage+1)
        state[op._id] = o
        return o
      else:
        try:
          o = {op:{k:cls.analyze(store, cls.analyze_recent_load_of(store, op, k), state, stage=stage+1) for k in cls.decoded_registers_of_set(op.p[0])}}
          state[op._id] = o
          return o
        except cls.RegisterDecodeError:
          state[op._id] = None
          return None
    else:
      return None

  @classmethod
  def analyze_recent_static_load_of(cls, store: Store, op: Op) -> Optional[Op]:
    assert op.t == 'id' and any(op.v.startswith(x) for x in ['sget-'])
    target = op.p[1].v
    for o in itertools.chain(cls.looking_behind_from(store, op), store.query().sputs(target)):
      if o.t == 'id' and o.v.startswith('sput-'):
        if o.p[1].v == target:
          return o
    else:
      ui.debug(f"analyze_recent_static_load_of: failed static trace: {op!r}")
      return None

  @classmethod
  def analyze_load(cls, store: Store, op: Op) -> FrozenSet[str]:
    if op.t == 'id':
      if any(op.v.startswith(x) for x in ['const','new-','move','array-length','aget-','sget-','iget-']):
        return cls.decoded_registers_of_set(op.p[0])
      elif any(op.v.startswith(x) for x in ['invoke-direct', 'invoke-virtual', 'invoke-interface']):
        # Imply modification of "this"
        return frozenset(cls.decoded_registers_of_list(op.p[0])[:1])
    return frozenset()

  @classmethod
  def analyze_recent_load_of(cls, store: Store, from_: Op, reg: str, stage: int = 0) -> Optional[Op]:
    for o in cls.looking_behind_from(store, from_):
      if o.t == 'id':
        if reg in cls.analyze_load(store, o):
          return o
    if reg.startswith('p'):
      index = int(reg.replace('p', ''))
      for caller in CodeFlows.callers_of(store, from_):
        if store.query().qualname_of(from_) != store.query().qualname_of(caller):
          caller_reg = cls.decoded_registers_of_list(caller.p[0])[index]
          ui.debug(f"analyze_recent_load_of: retrace: {from_!r} [{reg}] <-> {caller!r} [{caller_reg}] [stage: {stage}]")
          if stage < 5:
            retraced = cls.analyze_recent_load_of(store, caller, caller_reg, stage=stage+1)
            if retraced:
              return retraced
    return None

  # TBD: tracing on static-array fields
  @classmethod
  def analyze_recent_array_load_of(cls, store: Store, from_: Op, reg: str) -> Optional[Op]:
    return cls.analyze_recent_load_of(store, from_, reg)

  # TBD: tracing on static-instance fields
  @classmethod
  def analyze_recent_instance_load_of(cls, store: Store, op: Op) -> Optional[Op]:
    assert len(op.p) == 3
    assert op.t == 'id' and any(op.v.startswith(x) for x in ['iget-'])
    field = op.p[2].v
    for o in itertools.chain(cls.looking_behind_from(store, op), store.query().iputs(field)):
      if o.t == 'id' and o.v.startswith('iput-') and o.p[2].v == field:
        return o
    return None

  @classmethod
  def analyze_recent_invocation(cls, store: Store, from_: Op) -> Optional[Op]:
    for o in cls.looking_behind_from(store, from_):
      if o.t == 'id' and o.v.startswith('invoke'):
        return o
    return None
