from __future__ import annotations
from typing import TYPE_CHECKING

import itertools
from contextlib import contextmanager

from trueseeing.core.ui import ui
from trueseeing.core.android.model.code import Op

if TYPE_CHECKING:
  from typing import List, Any, Iterable, Mapping, Set, Optional, FrozenSet, Union, Dict, Iterator
  from typing_extensions import Final
  from trueseeing.core.android.db import Query

  DataGraph = Union[Op, Mapping[Op, Any]]

class CodeFlow:
  def __init__(self, q: Query) -> None:
    self._q = q

  def callers_of(self, method: Op) -> Iterable[Op]:
    yield from self._q.callers_of(method)

  def callstacks_of(self, method: Op) -> Mapping[Op, Any]:
    o = dict()
    for m in self.callers_of(method):
      o[m] = self.callstacks_of(m)
    return o

class DataFlow:
  _q: Query
  _default_max_graph_size: Final[int] = 2 * 1048576

  _max_graph_size: int = _default_max_graph_size

  class NoSuchValueError(Exception):
    pass

  class RegisterDecodeError(Exception):
    pass

  class GraphSizeError(Exception):
    pass

  def __init__(self, q: Query) -> None:
    self._q = q

  @classmethod
  def get_max_graph_size(cls) -> int:
    return cls._max_graph_size

  @classmethod
  def set_max_graph_size(cls, l: Optional[int]) -> int:
    o = cls._max_graph_size
    if l is not None and l != cls._default_max_graph_size:
      ui.info('using graph size limit: {} nodes'.format(l))
      cls._max_graph_size = l
    else:
      cls._max_graph_size = cls._default_max_graph_size
    return o

  @classmethod
  @contextmanager
  def apply_max_graph_size(cls, l: Optional[int]) -> Iterator[None]:
    try:
      o = cls.set_max_graph_size(l)
      yield None
    finally:
      cls.set_max_graph_size(o)

  def likely_calling_in(self, ops: List[Op]) -> None:
    pass

  def into(self, o: Op) -> Optional[Union[Op, Mapping[Op, Any]]]:
    return self.analyze(o)

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
    elif ref.t == 'reflike' and ref.v == '{},': # XXX
      return type_([])
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
  def looking_behind_from(self, op: Op) -> Iterable[Op]:
    focus = None
    for o in self._q.reversed_insns_in_method(op):
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

  def solved_constant_data_in_invocation(self, invokation_op: Op, index: int) -> str:
    assert invokation_op.t == 'id' and invokation_op.v.startswith('invoke')
    graph = self.analyze(invokation_op)
    try:
      reg = self.decoded_registers_of_list(invokation_op.p[0])[index + (0 if ('-static' in invokation_op.v) else 1)]
    except IndexError:
      raise self.NoSuchValueError(f'argument not found at index {index}')
    if graph:
      try:
        arg = graph[invokation_op][reg] # type: ignore[index]
        if arg.t == 'id' and arg.v.startswith('const'):
          return arg.p[1].v # type: ignore[no-any-return]
        else:
          raise self.NoSuchValueError(f'not a compile-time constant: {arg!r}')
      except (KeyError, AttributeError):
        raise self.NoSuchValueError(f'not a compile-time constant: {arg!r}')
    else:
      raise self.NoSuchValueError(f'not a compile-time constant: {arg!r}')

  @classmethod
  def walk_dict_values(cls, d: DataGraph) -> Iterable[Optional[Op]]:
    try:
      for v in d.values(): # type: ignore[union-attr]
        yield from cls.walk_dict_values(v)
    except AttributeError:
      yield d # type:ignore[misc]

  def solved_possible_constant_data_in_invocation(self, invokation_op: Op, index: int) -> Set[str]:
    assert invokation_op.t == 'id' and invokation_op.v.startswith('invoke')
    graph = self.analyze(invokation_op)
    reg = self.decoded_registers_of_list(invokation_op.p[0])[index + (0 if ('-static' in invokation_op.v) else 1)]
    if graph:
      n = graph[invokation_op][reg] # type: ignore[index]
      return {x.p[1].v for x in self.walk_dict_values(n) if x is not None and x.t == 'id' and x.v.startswith('const')}
    else:
      return set()

  def solved_typeset_in_invocation(self, invokation_op: Op, index: int) -> Set[Any]:
    assert invokation_op.t == 'id' and invokation_op.v.startswith('invoke')
    graph = self.analyze(invokation_op)
    reg = self.decoded_registers_of_list(invokation_op.p[0])[index + (0 if ('-static' in invokation_op.v) else 1)]
    if graph:
      arg = graph[invokation_op][reg] # type: ignore[index]

      return {self._assumed_target_type_of_op(x) for x in self.walk_dict_values(arg) if x is not None and x.t == 'id'}
    else:
      return set()

  @staticmethod
  def _assumed_target_type_of_op(x: Op) -> str:
    assert x.t == 'id'
    if x.v.startswith('const/4'):
      return 'Ljava/lang/Integer;'
    elif x.v.startswith('const-string'):
      return 'Ljava/lang/String;'
    elif x.v.startswith('new-array'):
      return x.p[2].v
    else:
      return 'Ljava/lang/Object;'

  @classmethod
  def _approximated_size_of_graph(cls, d: Optional[DataGraph], *, _cache:Optional[Dict[int, int]] = None) -> int:
    if _cache is None:
      _cache = dict()

    if d is None:
      return 0
    elif isinstance(d, Op):
      return 1
    elif isinstance(d, dict):
      o = 0
      assert len(d) == 1
      for k,v in d.items():
        assert isinstance(k, Op)
        assert k._id is not None
        if k._id in _cache:
          return _cache[k._id]
        else:
          for vk, vv in v.items():
            assert isinstance(vk, str)
            o += cls._approximated_size_of_graph(vv, _cache=_cache)
          _cache[k._id] = o
      return o
    else:
      assert False

  @classmethod
  def _check_graph(cls, d: Optional[DataGraph]) -> int:
    n = cls._approximated_size_of_graph(d)
    if n > cls._max_graph_size:
      raise cls.GraphSizeError()
    return n

  def analyze(self, op: Optional[Op], state:Optional[Dict[int, Any]]=None, stage:int = 0) -> Optional[DataGraph]:
    if op is None or stage > 64: # XXX: Is it sufficient? Might be better if we make it tunable?
      return None
    if state is None:
      state = dict()

    o: Optional[DataGraph] = None

    if op.t == 'id':
      assert op._id is not None
      if op._id in state:
        return state[op._id] # type: ignore[no-any-return]
      try:
        if any(op.v.startswith(x) for x in ['const','new-','move-exception']):
          o = op
          state[op._id] = o
          return o
        elif op.v in ['move', 'array-length']:
          o = {op:{k:self.analyze(self.analyze_recent_load_of(op, k), state, stage=stage+1) for k in self.decoded_registers_of_set(op.p[1])}}
          ui.debug('analyze: op #{id} stage: {stage} ({mode}) -> nodes: {nodes}'.format(mode='move', id=op._id, stage=stage, nodes=self._check_graph(o)))
          state[op._id] = o
          return o
        elif any(op.v.startswith(x) for x in ['aget-']):
          assert len(op.p) == 3
          o = {op:{k:self.analyze(self.analyze_recent_array_load_of(op, k), state, stage=stage+1) for k in (self.decoded_registers_of_set(op.p[1]) | self.decoded_registers_of_set(op.p[2]))}}
          ui.debug('analyze: op #{id} stage: {stage} ({mode}) -> nodes: {nodes}'.format(mode='aget', id=op._id, stage=stage, nodes=self._check_graph(o)))
          state[op._id] = o
          return o
        elif any(op.v.startswith(x) for x in ['sget-']):
          assert len(op.p) == 2
          o = {op:{k:self.analyze(self.analyze_recent_static_load_of(op), state, stage=stage+1) for k in self.decoded_registers_of_set(op.p[0])}}
          ui.debug('analyze: op #{id} stage: {stage} ({mode}) -> nodes: {nodes}'.format(mode='sget', id=op._id, stage=stage, nodes=self._check_graph(o)))
          state[op._id] = o
          return o
        elif any(op.v.startswith(x) for x in ['iget-']):
          assert len(op.p) == 3
          o = {op:{k:self.analyze(self.analyze_recent_instance_load_of(op), state, stage=stage+1) for k in self.decoded_registers_of_set(op.p[0])}}
          ui.debug('analyze: op #{id} stage: {stage} ({mode}) -> nodes: {nodes}'.format(mode='iget', id=op._id, stage=stage, nodes=self._check_graph(o)))
          state[op._id] = o
          return o
        elif op.v.startswith('move-result'):
          o = self.analyze(self.analyze_recent_invocation(op), state, stage=stage+1)
          ui.debug('analyze: op #{id} stage: {stage} ({mode}) -> nodes: {nodes}'.format(mode='move-result', id=op._id, stage=stage, nodes=self._check_graph(o)))
          state[op._id] = o
          return o
        else:
          try:
            o = {op:{k:self.analyze(self.analyze_recent_load_of(op, k), state, stage=stage+1) for k in self.decoded_registers_of_set(op.p[0])}}
            ui.debug('analyze: op #{id} stage: {stage} ({mode}) -> nodes: {nodes}'.format(mode='gen.', id=op._id, stage=stage, nodes=self._check_graph(o)))
            state[op._id] = o
            return o
          except self.RegisterDecodeError:
            state[op._id] = None
            return None
      except self.GraphSizeError:
        ui.warn('analyze: op #{id} stage: {stage}: too many nodes'.format(id=op._id, stage=stage))
        state[op._id] = None
        return None
    else:
      return None

  def analyze_recent_static_load_of(self, op: Op) -> Optional[Op]:
    assert op.t == 'id' and any(op.v.startswith(x) for x in ['sget-'])
    target = op.p[1].v
    for o in itertools.chain(self.looking_behind_from(op), self._q.sputs(target)):
      if o.t == 'id' and o.v.startswith('sput-'):
        if o.p[1].v == target:
          return o
    else:
      ui.debug(f"analyze_recent_static_load_of: failed static trace: {op!r}")
      return None

  def analyze_load(self, op: Op) -> FrozenSet[str]:
    if op.t == 'id':
      if any(op.v.startswith(x) for x in ['const','new-','move','array-length','aget-','sget-','iget-']):
        return self.decoded_registers_of_set(op.p[0])
      elif any(op.v.startswith(x) for x in ['invoke-direct', 'invoke-virtual', 'invoke-interface']):
        # Imply modification of "this"
        return frozenset(self.decoded_registers_of_list(op.p[0])[:1])
    return frozenset()

  def analyze_recent_load_of(self, from_: Op, reg: str, stage: int = 0) -> Optional[Op]:
    for o in self.looking_behind_from(from_):
      if o.t == 'id':
        if reg in self.analyze_load(o):
          return o
    if reg.startswith('p'):
      index = int(reg.replace('p', ''))
      for caller in CodeFlow(self._q).callers_of(from_):
        if self._q.qualname_of(from_) != self._q.qualname_of(caller):
          caller_reg = self.decoded_registers_of_list(caller.p[0])[index]
          ui.debug(f"analyze_recent_load_of: retrace: {from_!r} [{reg}] <-> {caller!r} [{caller_reg}] [stage: {stage}]")
          if stage < 5:
            retraced = self.analyze_recent_load_of(caller, caller_reg, stage=stage+1)
            if retraced:
              return retraced
    return None

  # TBD: tracing on static-array fields
  def analyze_recent_array_load_of(self, from_: Op, reg: str) -> Optional[Op]:
    return self.analyze_recent_load_of(from_, reg)

  # TBD: tracing on static-instance fields
  def analyze_recent_instance_load_of(self, op: Op) -> Optional[Op]:
    assert len(op.p) == 3
    assert op.t == 'id' and any(op.v.startswith(x) for x in ['iget-'])
    field = op.p[2].v
    for o in itertools.chain(self.looking_behind_from(op), self._q.iputs(field)):
      if o.t == 'id' and o.v.startswith('iput-') and o.p[2].v == field:
        return o
    return None

  def analyze_recent_invocation(self, from_: Op) -> Optional[Op]:
    for o in self.looking_behind_from(from_):
      if o.t == 'id' and o.v.startswith('invoke'):
        return o
    return None
