from __future__ import annotations
from typing import TYPE_CHECKING

import itertools
from contextlib import contextmanager

from trueseeing.core.ui import ui
from trueseeing.core.android.model import Op
from trueseeing.core.android.analyze.op import OpAnalyzer

if TYPE_CHECKING:
  from typing import List, Any, Iterable, Mapping, Set, Optional, FrozenSet, Union, Dict, Iterator
  from typing_extensions import Final
  from trueseeing.core.android.db import APKQuery
  from trueseeing.core.android.model import Token

  DataGraph = Union[Op, Mapping[Op, Any]]

class CodeFlow:
  def __init__(self, q: APKQuery) -> None:
    self._q = q

  def callers_of(self, method_addr: int) -> Iterator[Op]:
    yield from self._q.callers_of(method_addr)

  def callstacks_of(self, method_addr: int) -> Mapping[Op, Any]:
    o = dict()
    for caller in self.callers_of(method_addr):
      o[caller] = self.callstacks_of(caller.addr)
    return o

class DataFlow:
  _q: APKQuery
  _default_max_graph_size: Final[int] = 2 * 1048576
  _an = OpAnalyzer()

  _max_graph_size: int = _default_max_graph_size

  class NoSuchValueError(Exception):
    pass

  class UnsolvableValueError(NoSuchValueError):
    def __init__(self, graph: Optional[DataGraph]) -> None:
      self.graph = graph

  class RegisterDecodeError(Exception):
    pass

  class GraphSizeError(Exception):
    pass

  def __init__(self, q: APKQuery) -> None:
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

  def into(self, o: Op) -> Optional[DataGraph]:
    return self.analyze(o)

  @classmethod
  def _decoded_registers_of(cls, ref: Token, type_: Any = frozenset) -> Any:
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
  def decoded_registers_of_list(cls, ref: Token) -> List[str]:
    o: List[str] = cls._decoded_registers_of(ref, list)
    return o

  @classmethod
  def decoded_registers_of_set(cls, ref: Token) -> FrozenSet[str]:
    o: FrozenSet[str] = cls._decoded_registers_of(ref, frozenset)
    return o

  # TBD: pack as SQL function
  def looking_behind_from(self, op: Op) -> Iterator[Op]:
    focus = None
    for o in self._q.reversed_insns_in_method(op.addr):
      xs = list(self._an.tokenize(o))
      stem = xs[0]
      if focus is None:
        if stem.t != 'label':
          yield o
        else:
          if not stem.v.startswith("try_"):
            focus = stem.v
      else:
        if stem.t != 'id' or not any(p.v == focus for p in xs[1:]):
          continue
        else:
          focus = None

  def solved_constant_data_in_invocation(self, invokation_op: Op, index: int) -> str:
    assert self._an.get_insn(invokation_op).startswith('invoke')
    graph = self.analyze(invokation_op)
    try:
      reg = self.decoded_registers_of_list(self._an.get_param(invokation_op, 0))[index + (0 if ('-static' in self._an.get_insn(invokation_op)) else 1)]
    except IndexError:
      raise self.NoSuchValueError(f'argument not found at index {index}')
    if graph:
      try:
        arg: Op = graph[invokation_op][reg] # type: ignore
        if self._an.get_insn(arg).startswith('const'):
          return self._an.get_param(arg, 1).v
        else:
          raise self.UnsolvableValueError(graph=arg)
      except (KeyError, AttributeError):
        raise self.UnsolvableValueError(graph=graph)
    else:
      raise self.UnsolvableValueError(graph=None)

  @classmethod
  def walk_dict_values(cls, d: DataGraph) -> Iterable[Optional[Op]]:
    try:
      for v in d.values(): # type: ignore[union-attr]
        yield from cls.walk_dict_values(v)
    except AttributeError:
      yield d # type:ignore[misc]

  def solved_possible_constant_data_in_invocation(self, invokation_op: Op, index: int) -> Set[str]:
    assert self._an.get_insn(invokation_op).startswith('invoke')
    graph = self.analyze(invokation_op)
    reg = self.decoded_registers_of_list(self._an.get_param(invokation_op, 0))[index + (0 if ('-static' in self._an.get_insn(invokation_op)) else 1)]
    if graph:
      n: DataGraph = graph[invokation_op][reg] # type: ignore
      return {self._an.get_param(x, 1).v for x in self.walk_dict_values(n) if x is not None and self._an.get_insn(x).startswith('const')}
    else:
      return set()

  def solved_typeset_in_invocation(self, invokation_op: Op, index: int) -> Set[Any]:
    assert self._an.get_insn(invokation_op).startswith('invoke')
    graph = self.analyze(invokation_op)
    reg = self.decoded_registers_of_list(self._an.get_param(invokation_op, 0))[index + (0 if ('-static' in self._an.get_insn(invokation_op)) else 1)]
    if graph:
      arg: DataGraph = graph[invokation_op][reg] # type: ignore
      return {self._assumed_target_type_of_op(x) for x in self.walk_dict_values(arg) if x is not None}
    else:
      return set()

  @classmethod
  def _assumed_target_type_of_op(cls, x: Op) -> str:
    mn = cls._an.get_insn(x)
    if mn.startswith('const/4'):
      return 'Ljava/lang/Integer;'
    elif mn.startswith('const-string'):
      return 'Ljava/lang/String;'
    elif mn.startswith('new-array'):
      return cls._an.get_param(x, 2).v
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
        assert k.addr is not None
        if k.addr in _cache:
          return _cache[k.addr]
        else:
          for vk, vv in v.items():
            assert isinstance(vk, str)
            o += cls._approximated_size_of_graph(vv, _cache=_cache)
          _cache[k.addr] = o
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

    mn = self._an.get_insn(op)
    addr = op.addr

    assert addr is not None
    if addr in state:
      return state[addr] # type: ignore[no-any-return]
    try:
      if any(mn.startswith(x) for x in ['const','new-','move-exception']):
        o = op
        state[addr] = o
        return o
      elif mn in ['move', 'array-length']:
        o = {op:{k:self.analyze(self.analyze_recent_load_of(op, k), state, stage=stage+1) for k in self.decoded_registers_of_set(self._an.get_param(op, 1))}}
        ui.debug('analyze: 0x{addr:08x} stage: {stage} ({mode}) -> nodes: {nodes}'.format(mode='move', addr=addr, stage=stage, nodes=self._check_graph(o)))
        state[addr] = o
        return o
      elif any(mn.startswith(x) for x in ['aget-']):
        assert self._an.get_param_count(op) == 3
        o = {op:{k:self.analyze(self.analyze_recent_array_load_of(op, k), state, stage=stage+1) for k in (self.decoded_registers_of_set(self._an.get_param(op, 1)) | self.decoded_registers_of_set(self._an.get_param(op, 2)))}}
        ui.debug('analyze: 0x{addr:08x} stage: {stage} ({mode}) -> nodes: {nodes}'.format(mode='aget', addr=addr, stage=stage, nodes=self._check_graph(o)))
        state[addr] = o
        return o
      elif any(mn.startswith(x) for x in ['sget-']):
        assert self._an.get_param_count(op) == 2
        o = {op:{k:self.analyze(self.analyze_recent_static_load_of(op), state, stage=stage+1) for k in self.decoded_registers_of_set(self._an.get_param(op, 0))}}
        ui.debug('analyze: 0x{addr:08x} stage: {stage} ({mode}) -> nodes: {nodes}'.format(mode='sget', addr=addr, stage=stage, nodes=self._check_graph(o)))
        state[addr] = o
        return o
      elif any(mn.startswith(x) for x in ['iget-']):
        assert self._an.get_param_count(op) == 3
        o = {op:{k:self.analyze(self.analyze_recent_instance_load_of(op), state, stage=stage+1) for k in self.decoded_registers_of_set(self._an.get_param(op, 0))}}
        ui.debug('analyze: 0x{addr:08x} stage: {stage} ({mode}) -> nodes: {nodes}'.format(mode='iget', addr=addr, stage=stage, nodes=self._check_graph(o)))
        state[addr] = o
        return o
      elif mn.startswith('move-result'):
        o = self.analyze(self.analyze_recent_invocation(op), state, stage=stage+1)
        ui.debug('analyze: 0x{addr:08x} stage: {stage} ({mode}) -> nodes: {nodes}'.format(mode='move-result', addr=addr, stage=stage, nodes=self._check_graph(o)))
        state[addr] = o
        return o
      else:
        try:
          o = {op:{k:self.analyze(self.analyze_recent_load_of(op, k), state, stage=stage+1) for k in self.decoded_registers_of_set(self._an.get_param(op, 0))}}
          ui.debug('analyze: 0x{addr:08x} stage: {stage} ({mode}) -> nodes: {nodes}'.format(mode='gen.', addr=addr, stage=stage, nodes=self._check_graph(o)))
          state[addr] = o
          return o
        except self.RegisterDecodeError:
          state[addr] = None
          return None
    except self.GraphSizeError:
      ui.warn('analyze: 0x{addr:08x} stage: {stage}: too many nodes'.format(addr=addr, stage=stage))
      state[addr] = None
      return None

  def analyze_recent_static_load_of(self, op: Op) -> Optional[Op]:
    assert self._an.get_insn(op).startswith('sget-')
    target = self._an.get_param(op, 1).v
    for o in itertools.chain(self.looking_behind_from(op), self._q.sputs(target)):
      try:
        if self._an.get_insn(o).startswith('sput-'):
          if self._an.get_param(o, 1).v == target:
            return o
      except ValueError:
        pass
    else:
      ui.debug(f"analyze_recent_static_load_of: failed static trace: {op!r}")
      return None

  def analyze_load(self, op: Op) -> FrozenSet[str]:
    try:
      v = self._an.get_insn(op)
    except ValueError:
      return frozenset()
    else:
      if any(v.startswith(x) for x in ['const','new-','move','array-length','aget-','sget-','iget-']):
        return self.decoded_registers_of_set(self._an.get_param(op, 0))
      elif any(v.startswith(x) for x in ['invoke-direct', 'invoke-virtual', 'invoke-interface']):
        # Imply modification of "this"
        return frozenset(self.decoded_registers_of_list(self._an.get_param(op, 0))[:1])
      return frozenset()

  def analyze_recent_load_of(self, from_: Op, reg: str, stage: int = 0) -> Optional[Op]:
    for o in self.looking_behind_from(from_):
      if self._an.get_mnemonic(o).t == 'id':
        if reg in self.analyze_load(o):
          return o
    if reg.startswith('p'):
      index = int(reg.replace('p', ''))
      for caller in CodeFlow(self._q).callers_of(from_.addr):
        if not self._q.in_same_mod(from_.addr, caller.addr):
          caller_reg = self.decoded_registers_of_list(self._an.get_param(caller, 0))[index]
          if ui.is_debugging:
            ui.debug('analyze_recent_load_of: retracing [{stage}]: {reg} 0x{addr:08x} [{qn}] -> {caller_reg} 0x{caller_addr:08x} [{caller_qn}] {{{caller_l}}}'.format(
              stage=stage, reg=reg, addr=from_.addr, qn=self._q.qualname_of(from_.addr),
              caller_reg=caller_reg, caller_addr=caller.addr, caller_qn=self._q.qualname_of(caller.addr),
              caller_l=self._q.op_get(caller.addr).l,
            ))
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
    assert self._an.get_param_count(op) == 3
    assert self._an.get_insn(op).startswith('iget-')
    field = self._an.get_param(op, 2).v
    for o in itertools.chain(self.looking_behind_from(op), self._q.iputs(field)):
      try:
        if self._an.get_insn(o).startswith('iput-') and self._an.get_param(o, 2).v == field:
          return o
      except ValueError:
        pass
    return None

  def analyze_recent_invocation(self, from_: Op) -> Optional[Op]:
    for o in self.looking_behind_from(from_):
      try:
        if self._an.get_insn(o).startswith('invoke'):
          return o
      except ValueError:
        pass
    return None
