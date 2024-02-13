from __future__ import annotations
from typing import TYPE_CHECKING

from contextlib import contextmanager
from trueseeing.core.android.model.code import Op
from trueseeing.core.model.issue import Issue
from trueseeing.core.tools import noneif

if TYPE_CHECKING:
  from typing import Any, Iterable, Tuple, Dict, Optional, Iterator, List, Set
  from trueseeing.core.android.store import Store
  from trueseeing.core.android.model.code import InvocationPattern
  from trueseeing.core.model.issue import IssueConfidence

class StorePrep:
  def __init__(self, c: Any) -> None:
    self.c = c

  def stage0(self) -> None:
    from importlib.resources import files
    self.c.executescript((files('trueseeing')/'libs'/'android'/'store.s.sql').read_text())

  def stage1(self) -> None:
    from importlib.resources import files
    from trueseeing.core.env import get_cache_schema_id
    self.c.execute('pragma user_version={}'.format(get_cache_schema_id()))
    self.c.executescript((files('trueseeing')/'libs'/'android'/'store.0.sql').read_text())

  def stage2(self) -> None:
    from importlib.resources import files
    self.c.executescript((files('trueseeing')/'libs'/'android'/'store.1.sql').read_text())

  def require_valid_schema(self) -> None:
    from trueseeing.core.env import get_cache_schema_id
    v, = self.c.execute('pragma user_version').fetchone()
    if v != get_cache_schema_id():
      from trueseeing.core.exc import InvalidSchemaError
      raise InvalidSchemaError()

class FileTablePrep:
  def __init__(self, c: Any) -> None:
    self.c = c

  def prepare(self) -> None:
    from importlib.resources import files
    self.c.executescript((files('trueseeing')/'libs'/'files.0.sql').read_text())

class Query:
  def __init__(self, *, store: Optional[Store] = None, c: Any = None) -> None:
    if c is not None:
      self.db = c
    elif store is not None:
      self.db = store.db
    else:
      raise RuntimeError('store or c is required')

  @contextmanager
  def scoped(self) -> Iterator[Query]:
    with self.db:
      yield self

  @staticmethod
  def _op_from_row(r: Tuple[Any, ...]) -> Op:
    return Op(r[1], r[2], [Op(o[1], o[2], [], id_=o[0]) for o in (r[x:x + 3] for x in range(3, 30, 3)) if o[0] is not None], id_=r[0])

  def reversed_insns_in_method(self, from_: Op) -> Iterable[Op]:
    for r in self.db.execute('select op as _0, t as _1, v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from op_vecs where op in (select op from ops_method where op<(select op from ops_p where p=:from_op) and method=(select method from ops_method where op=(select op from ops_p where p=:from_op))) order by op desc', dict(from_op=from_._id)):
      yield self._op_from_row(r)

  @staticmethod
  def _cond_as_sql(param: Dict[str, Any], t: Optional[str], v: Optional[str]) -> Tuple[Dict[str, str], Dict[str, Any]]:
    cond = dict(cond='1')
    if t is not None or v is not None:
      cond.update(dict(cond=' and '.join(['t=:t' if t is not None else '1', 'v like :v' if v is not None else '1'])))
      param.update({p:q for p,q in dict(t=t, v=v).items() if q is not None})
    return cond, param

  def find_recent_in_method(self, from_: Op, t: str, v: str) -> Iterable[Op]:
    cond, param = self._cond_as_sql(dict(from_op=from_._id), t, v)
    for r in self.db.execute(f'select op as _0, t as _1, v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from op_vecs where op in (select op from ops_method where op<=(select op from ops_p where p=:from_op) and method=(select method from ops_method where op=(select op from ops_p where p=:from_op))) and ({cond}) order by op desc', param):
      yield self._op_from_row(r)

  def ops(self) -> Iterable[Op]:
    for r in self.db.execute('select op as _0, t as _1, v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from op_vecs'):
      yield self._op_from_row(r)

  def invocations(self, pattern: InvocationPattern) -> Iterable[Op]:
    for r in self.db.execute(f'select op as _0, t as _1, op_vecs.v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from op_vecs where op in (select op from interests_invokes where v like \'{pattern.insn}%\' and target regexp \'{pattern.value}\')'):
      yield self._op_from_row(r)

  def invocations_in_class(self, class_: Op, pattern: InvocationPattern) -> Iterable[Op]:
    for r in self.db.execute(f'select op as _0, t as _1, op_vecs.v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from op_vecs where op in (select op from interests_invokes join ops_class using (op) where class=(select class from ops_class where op=:class_) and v like \'{pattern.insn}%\' and target regexp \'{pattern.value}\')', dict(class_=class_._id)):
      yield self._op_from_row(r)

  def consts(self, pattern: InvocationPattern) -> Iterable[Op]:
    for r in self.db.execute(f'select op as _0, t as _1, op_vecs.v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from op_vecs where op in (select op from interests_consts where v like \'{pattern.insn}%\' and target regexp \'{pattern.value}\')'):
      yield self._op_from_row(r)

  def consts_in_class(self, class_: Op, pattern: InvocationPattern) -> Iterable[Op]:
    for r in self.db.execute(f'select op as _0, t as _1, op_vecs.v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from op_vecs where op in (select op from interests_consts join ops_class using (op) where class=(select class from ops_class where op=:class_) and v like \'{pattern.insn}%\' and target regexp \'{pattern.value}\')', dict(class_=class_._id)):
      yield self._op_from_row(r)

  def consts_in_package(self, name: str, pattern: InvocationPattern) -> Iterable[Op]:
    for r in self.db.execute(f'select op as _0, t as _1, op_vecs.v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from op_vecs where op in (select op from interests_consts join ops_class using (op) where class in (select class from class_class_name where class_name like :pat) and v like \'{pattern.insn}%\' and target regexp \'{pattern.value}\')', dict(pat=self._get_smali_forward_like_pattern_of_package(name))):
      yield self._op_from_row(r)

  def sputs(self, target: str) -> Iterable[Op]:
    for r in self.db.execute('select op as _0, t as _1, op_vecs.v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from op_vecs where op in (select op from interests_sputs where target=:target)', dict(target=target)):
      yield self._op_from_row(r)

  def iputs(self, target: str) -> Iterable[Op]:
    for r in self.db.execute('select op as _0, t as _1, op_vecs.v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from op_vecs where op in (select op from interests_iputs where target=:target)', dict(target=target)):
      yield self._op_from_row(r)

  def ops_of(self, insn: str) -> Iterable[Op]:
    for r in self.db.execute('select op as _0, t as _1, op_vecs.v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from op_vecs where v=:insn', dict(insn=insn)):
      yield self._op_from_row(r)

  def classes_has_method_named(self, pattern: str) -> Iterable[Op]:
    for r in self.db.execute(f'select op as _0, t as _1, v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from op_vecs where op in (select class from methods_class join method_method_name using (method) where method_name regexp \'{pattern}\')'):
      yield self._op_from_row(r)

  def classes_extends_has_method_named(self, method: str, extends: str) -> Iterable[Op]:
    for r in self.db.execute(f'select op as _0, t as _1, v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from op_vecs where op in (select class from classes_extends_name join methods_class using (class) join method_method_name using (method) where method_name regexp \'{method}\' and extends_name regexp \'{extends}\')'):
      yield self._op_from_row(r)

  def classes_implements_has_method_named(self, method: str, implements: str) -> Iterable[Op]:
    for r in self.db.execute(f'select op as _0, t as _1, v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from op_vecs where op in (select class from classes_implements_name join methods_class using (class) join method_method_name using (method) where method_name regexp \'{method}\' and implements_name regexp \'{implements}\')'):
      yield self._op_from_row(r)

  def qualname_of(self, op: Optional[Op]) -> Optional[str]:
    if op:
      for o, in self.db.execute('select qualname from method_qualname join ops_method using (method) where op=:op', dict(op=op._id)):
        return o # type: ignore[no-any-return]
    return None

  def class_name_of(self, op: Optional[Op]) -> Optional[str]:
    if op:
      for o, in self.db.execute('select class_name from class_class_name join ops_class using (class) where op=:op', dict(op=op._id)):
        return o # type: ignore[no-any-return]
    return None

  def _get_smali_forward_like_pattern_of_package(self, name: str) -> str:
    return r'L{}/%'.format(name.replace('.', '/'))

  def classes_in_package_named(self, name: str) -> Iterable[Op]:
    for r in self.db.execute('select op as _0, t as _1, op_vecs.v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from op_vecs where op in (select class from class_class_name where class_name like :pat)', dict(pat=self._get_smali_forward_like_pattern_of_package(name))):
      yield self._op_from_row(r)

  def method_call_target_of(self, op: Optional[Op]) -> Optional[str]:
    if op:
      for r in self.db.execute('select op as _0, t as _1, op_vecs.v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from op_vecs where op=(select op from interests_invokes where op=:op)', dict(op=op._id)):
        return r[8] # type: ignore[no-any-return]
    return None

  def callers_of(self, op: Op) -> Iterable[Op]:
    for r in self.db.execute('select op as _0, t as _1, op_vecs.v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from op_vecs where op in (select op from interests_invokes where target=(select qualname from method_qualname where method=(select method from ops_method where op=:op)))', dict(op=op._id)):
      yield self._op_from_row(r)

  def callers_of_method_named(self, pattern: InvocationPattern) -> Iterable[Op]:
    for r in self.db.execute(f'select op as _0, t as _1, op_vecs.v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from interests_invokes join op_vecs using (op) where target regexp \'{pattern}\''):
      yield self._op_from_row(r)

  def methods_in_class(self, method_name: str, related_class_name: str) -> Iterable[Op]:
    for r in self.db.execute('select op as _0, t as _1, v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from op_vecs where op in (select method from classes_extends_name left join classes_implements_name using (class) join methods_class using (class) join method_method_name using (method) where (extends_name like :class_pat or implements_name like :class_pat) and method_name like :method_pat)', dict(class_pat=f'%{related_class_name}%', method_pat=f'%{method_name}%')):
      yield self._op_from_row(r)

  def related_classes(self, related_class_name: str) -> Iterable[Op]:
    for r in self.db.execute('select op as _0, t as _1, v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from op_vecs where op in (select class from classes_extends_name left join classes_implements_name using (class) where (extends_name regexp :class_pat or implements_name regexp :class_pat))', dict(class_pat=related_class_name)):
      yield self._op_from_row(r)

  def matches_in_method(self, method: Op, pattern: InvocationPattern) -> Iterable[Op]:
    for r in self.db.execute(f'select op as _0, t as _1, v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from op_vecs where op in (select op from ops_method join ops using (op) where method=(select method from ops_method where op=:from_op) and v like \'{pattern.insn}%\') and v2 regexp \'{pattern.value}\'', dict(from_op=method._id)):
      yield self._op_from_row(r)

  def class_of_method(self, method: Op) -> Optional[Op]:
    for r in self.db.execute('select op as _0, t as _1, v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from op_vecs where op=(select class from ops_class where op=:from_op)', dict(from_op=method._id)):
      return self._op_from_row(r)
    return None

  def methods_with_modifier(self, pattern: str) -> Iterable[Op]:
    for r in self.db.execute('select op_vecs.op as _0, t as _1, v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from ops_method join op_vecs on (method=ops_method.op and method=op_vecs.op) where v=:pat or v2=:pat or v3=:pat or v4=:pat or v5=:pat or v6=:pat or v7=:pat or v8=:pat or v9=:pat', dict(pat=pattern)):
      yield Query._op_from_row(r)

  def file_find(self, pat: str, regex: bool = False) -> Iterable[str]:
    for f, in self.db.execute('select path from files where path {op} :pat'.format(op=('like' if not regex else 'regexp')), dict(pat=pat)):
      yield f

  def file_search(self, pat: bytes, regex: bool = False) -> Iterable[str]:
    for f, in self.db.execute('select path from files where blob {op} :pat'.format(op=('like' if not regex else 'regexp')), dict(pat=pat)):
      yield f

  def file_get(self, path: str, default: Optional[bytes] = None, patched: bool = False) -> Optional[bytes]:
    stmt0 = 'select blob from files where path=:path'
    stmt1 = 'select coalesce(B.blob, A.blob) as blob from files as A full outer join patches as B using (path) where path=:path'
    for b, in self.db.execute(stmt1 if patched else stmt0, dict(path=path)):
      return b # type:ignore[no-any-return]
    else:
      return default

  def file_get_xml(self, path: str, default: Any = None, patched: bool = False) -> Any:
    import lxml.etree as ET
    r = self.file_get(path, patched=patched)
    if r is not None:
      return ET.fromstring(r, parser=ET.XMLParser(recover=True))
    else:
      return default

  def file_enum(self, pat: Optional[str], patched: bool = False, regex: bool = False) -> Iterable[Tuple[str, bytes]]:
    if pat is not None:
      stmt0 = 'select path, blob from files where path {op} :pat'.format(op=('like' if not regex else 'regexp'))
      stmt1 = 'select path, coalesce(B.blob, A.blob) as blob from files as A full outer join patches as B using (path) where path {op} :pat'.format(op=('like' if not regex else 'regexp'))
      for n, o in self.db.execute(stmt1 if patched else stmt0, dict(pat=pat)):
        yield n, o
    else:
      stmt2 = 'select path, blob from files'
      stmt3 = 'select path, coalesce(B.blob, A.blob) as blob from files as A full outer join patches as B using (path)'
      for n, o in self.db.execute(stmt3 if patched else stmt2):
        yield n, o

  def file_count(self, pat: Optional[str], patched: bool = False, regex: bool = False) -> int:
    if pat is not None:
      stmt0 = 'select count(1) from files where path {op} :pat'.format(op=('like' if not regex else 'regexp'))
      stmt1 = 'select conut(1) from files as A full outer join patches as B using (path) where path {op} :pat'.format(op=('like' if not regex else 'regexp'))
      for nr, in self.db.execute(stmt1 if patched else stmt0, dict(pat=pat)):
        return nr # type:ignore[no-any-return]
    else:
      stmt2 = 'select count(1) from files'
      stmt3 = 'select count(1) from files as A full outer join patches as B using (path)'
      for nr, in self.db.execute(stmt3 if patched else stmt2):
        return nr # type:ignore[no-any-return]
    return 0

  def file_put_batch(self, gen: Iterable[Tuple[str, bytes]]) -> None:
    self.db.executemany('insert into files (path, blob) values (?,?)', gen)

  def patch_enum(self, pat: Optional[str]) -> Iterable[Tuple[str, bytes]]:
    if pat is not None:
      stmt0 = 'select path, blob from patches where path like :pat'
      for n, o in self.db.execute(stmt0, dict(pat=pat)):
        yield n, o
    else:
      stmt1 = 'select path, blob from patches'
      for n, o in self.db.execute(stmt1):
        yield n, o

  def patch_put(self, path: str, blob: bytes) -> None:
    self.db.execute('replace into patches (path, blob) values (:path,:blob)', dict(path=path, blob=blob))

  def patch_exists(self, path: Optional[str]) -> bool:
    stmt0 = 'select 1 from patches where path=:path'
    stmt1 = 'select 1 from patches'
    for r, in self.db.execute(stmt0 if path is not None else stmt1, dict(path=path)):
      return True
    else:
      return False

  def patch_clear(self) -> None:
    self.db.execute('delete from patches')

  def issue_count(self) -> int:
    for nr, in self.db.execute('select count(1) from analysis_issues'):
      return int(nr)
    else:
      return 0

  def issue_raise(self, i: Issue) -> None:
    assert i.score is not None
    self.db.execute(
      'insert or ignore into analysis_issues (sig, title, summary, descr, ref, sol, info0, info1, info2, cfd, score, cvss, aff0, aff1, aff2) values (:sigid, :title, :summary, :desc, :ref, :sol, :info0, :info1, :info2, :cfd, :score, :cvss, :aff0, :aff1, :aff2)',
      dict(
        sigid=i.sigid,
        title=i.title,
        cfd=self._issue_confidence_to_int(i.cfd),
        cvss=i.cvss,
        score=i.score,
        summary=noneif(i.summary, ''),
        desc=noneif(i.desc, ''),
        ref=noneif(i.ref, ''),
        sol=noneif(i.sol, ''),
        info0=noneif(i.info0, ''),
        info1=noneif(i.info1, ''),
        info2=noneif(i.info2, ''),
        aff0=noneif(i.aff0, ''),
        aff1=noneif(i.aff1, ''),
        aff2=noneif(i.aff2, ''),
      ))

  def issue_clear(self) -> None:
    self.db.execute('delete from analysis_issues')

  def issues(self) -> Iterable[Issue]:
    for m in self.db.execute('select sig, title, summary, descr, ref, sol, info0, info1, info2, cfd, score, cvss, aff0, aff1, aff2 from analysis_issues'):
      yield self._issue_from_row(m)

  def findings_list(self) -> Iterable[Tuple[int, Tuple[str, str, Optional[str], Optional[str], Optional[str], Optional[str], float, str]]]:
    for no, r in enumerate(self.db.execute('select distinct sig, title, summary, descr, ref, sol, score, cvss from analysis_issues order by score desc')):
      yield no, (
        r[0],
        r[1],
        r[2] if r[2] else None,
        r[3] if r[3] else None,
        r[4] if r[4] else None,
        r[5] if r[5] else None,
        r[6],
        r[7],
      )

  def issues_by_group(self, *, sig: str, title: str) -> Iterable[Issue]:
    for m in self.db.execute('select sig, title, summary, descr, ref, sol, info0, info1, info2, cfd, score, cvss, aff0, aff1, aff2 from analysis_issues where sig=:sig and title=:title order by score desc, cfd desc', dict(sig=sig, title=title)):
      yield self._issue_from_row(m)

  def op_get(self, k: int) -> Optional[Op]:
    for t,v in self.db.execute('select t,v from ops where op=?', (k, )):
      return Op(t, v)
    return None

  def op_store_ops(self, ops: Iterable[Op], c: Any = None) -> None:
    if c is None: c = self.db
    c.executemany('insert into ops(op,idx,t,v) values (?,?,?,?)', ((t._id, t._idx, t.t, t.v) for t in ops))

  def op_count_ops(self, c: Any = None) -> int:
    if c is None: c = self.db
    for cnt, in c.execute('select count(1) from ops where idx=0'):
      return cnt # type: ignore[no-any-return]
    return 0

  def op_store_classmap(self, classmap: Set[Tuple[int, int]], c: Any = None) -> int:
    if c is None: c = self.db
    c.executemany('insert into ops_class(class,op) select ?,op from ops where op between ? and ?', ((start, start, end) for start, end in classmap))
    return len(classmap)

  def op_generate_methodmap(self, c: Any = None) -> int:
    if c is None: c = self.db
    detected_methods = 0
    c.execute("create table tmp1 (op int primary key)")
    c.execute("create table tmp2 (op int primary key)")
    c.execute("insert into tmp1 select op from ops where t='directive' and v='method'")
    c.execute("insert into tmp2 select a.op as op from ops as a left join ops as c on (a.op=c.op-c.idx) where a.t='directive' and a.v='end' and c.idx=1 and c.v='method'")
    c.execute('insert into ops_method(method,op) select mm.sop as method,ops.op from (select tmp1.op as sop,(select min(op) from tmp2 where op>tmp1.op) as eop from tmp1) as mm left join ops on (ops.op between mm.sop and mm.eop)')
    for cnt, in c.execute('select count(1) from tmp1'):
      detected_methods = cnt
    c.execute("drop table tmp1")
    c.execute("drop table tmp2")
    return detected_methods

  def op_finalize(self) -> None:
    from trueseeing.core.android.db import StorePrep
    StorePrep(self.db).stage2()

  @classmethod
  def _issue_confidence_to_int(cls, c: IssueConfidence) -> int:
    return dict(certain=2, firm=1, tentative=0)[c]

  @classmethod
  def _issue_confidence_from_int(cls, c: int) -> IssueConfidence:
    m: List[IssueConfidence] = ['tentative', 'firm', 'certain']
    return m[c]

  @classmethod
  def _issue_from_row(cls, r: Tuple[Any, ...]) -> Issue:
    return Issue(
      sigid=r[0],
      title=r[1],
      cfd=cls._issue_confidence_from_int(r[9]),
      cvss=r[11],
      summary=r[2] if r[2] else None,
      desc=r[3] if r[3] else None,
      ref=r[4] if r[4] else None,
      sol=r[5] if r[5] else None,
      info0=r[6] if r[6] else None,
      info1=r[7] if r[7] else None,
      info2=r[8] if r[8] else None,
      aff0=r[12] if r[12] else None,
      aff1=r[13] if r[13] else None,
      aff2=r[14] if r[14] else None,
    )
