from __future__ import annotations
from typing import TYPE_CHECKING

from trueseeing.core.db import Query, StorePrep
from trueseeing.core.android.model import Op

if TYPE_CHECKING:
  from typing import Optional, Iterator
  from trueseeing.core.store import Store
  from trueseeing.core.android.model import InvocationPattern, Call

class APKStorePrep(StorePrep):
  def stage1(self) -> None:
    super().stage1()
    from importlib.resources import files
    self.c.executescript((files('trueseeing')/'libs'/'android'/'store.0.sql').read_text())

  def stage2(self) -> None:
    from importlib.resources import files
    self.c.executescript((files('trueseeing')/'libs'/'android'/'store.1.sql').read_text())

  def _get_cache_schema_id(self) -> int:
    return super()._get_cache_schema_id() ^ 0x48d42899

class APKQuery(Query):
  def __init__(self, store: Store) -> None:
    super().__init__(store)
    if store:
      from trueseeing.core.android.store import APKStore
      assert isinstance(store, APKStore)

  def _get_smali_forward_like_pattern_of_package(self, name: str, *, regex: bool = False) -> str:
    return r'L{}/{}'.format(name.replace('.', '/'), '' if regex else '%')

  def consts(self, pat: InvocationPattern) -> Iterator[Op]:
    for addr, l in self.db.execute('select addr, l from ops join xref_const using (addr) where insn like :insn and sym regexp :pat', dict(insn=f'{pat.insn}%', pat=pat.value)):
      yield Op(addr, l)

  def consts_in_package(self, name: str, pat: InvocationPattern) -> Iterator[Op]:
    for addr, l in self.db.execute('select addr, l from ops join xref_const using (addr) join map on (addr between low and high) where class like :pkg and insn like :insn and sym regexp :pat', dict(insn=f'{pat.insn}%', pat=pat.value, pkg=self._get_smali_forward_like_pattern_of_package(name))):
      yield Op(addr, l)

  def consts_in_class(self, addr: int, pat: InvocationPattern) -> Iterator[Op]:
    for addr, l in self.db.execute("select addr, l from ops join (select low, high from ops join map on (map_id=id) where addr=:addr) on (addr between low and high) join xref_const using (addr) where insn like :insn and sym regexp :pat", dict(addr=addr, insn=f'{pat.insn}%', pat=pat.value)):
      yield Op(addr, l)

  def sputs(self, target: str) -> Iterator[Op]:
    for addr, l in self.db.execute('select addr, l from ops join xref_sput using (addr) where sym=:sym', dict(sym=target)):
      yield Op(addr, l)

  def iputs(self, target: str) -> Iterator[Op]:
    for addr, l in self.db.execute('select addr, l from ops join xref_iput using (addr) where sym=:sym', dict(sym=target)):
      yield Op(addr, l)

  def op_get(self, addr: int) -> Op:
    for addr, l in self.db.execute("select addr, l from ops where addr=:addr", dict(addr=addr)):
      return Op(addr, l)
    raise IndexError()

  def ops_of(self, insn: str) -> Iterator[Op]:
    for addr, l in self.db.execute("select addr, l from ops join map on (map_id=id) where method is not null and l like :pat", dict(pat=f'    {insn} %')):
      yield Op(addr, l)

  def invocations(self, pat: InvocationPattern) -> Iterator[Op]:
    for addr, l in self.db.execute("select addr, l from ops join xref_invoke using (addr) where insn like :insn and sym regexp :pat", dict(insn=f'{pat.insn}%', pat=pat.value)):
      yield Op(addr, l)

  def invocations_in_class(self, addr: int, pat: InvocationPattern) -> Iterator[Op]:
    for addr, l in self.db.execute("select addr, l from ops join (select low, high from ops join map on (map_id=id) where addr=:addr) on (addr between low and high) join xref_invoke using (addr) where insn like :insn and sym regexp :pat", dict(addr=addr, insn=f'{pat.insn}%', pat=pat.value)):
      yield Op(addr, l)

  def callers_of(self, addr: int) -> Iterator[Op]:
    for addr, l in self.db.execute("select addr, l from ops join xref_invoke using (addr) where target=(select low from ops join map on (map_id=id) where method is not null and addr=:addr)", dict(addr=addr)):
      yield Op(addr, l)

  def qualname_of(self, addr: int) -> Optional[str]:
    for n, in self.db.execute("select class||'->'||method from ops join map on (map_id=id) where method is not null and addr=:addr", dict(addr=addr)):
      return n # type: ignore[no-any-return]
    return None

  def class_name_of(self, addr: int) -> Optional[str]:
    for n, in self.db.execute("select class from ops join map on (map_id=id) where addr=:addr", dict(addr=addr)):
      return n # type: ignore[no-any-return]
    return None

  def method_call_target_of(self, addr: Optional[int]) -> Optional[str]:
    if addr is not None:
      for sym, in self.db.execute('select sym from xref_invoke where addr=:addr', dict(addr=addr)):
        return sym # type: ignore[no-any-return]
    return None

  def reversed_insns_in_method(self, addr: int) -> Iterator[Op]:
    for addr, l in self.db.execute("select addr, l from ops where addr between (select low from ops join map on (map_id=id) where addr=:addr) and :addr-1 order by addr desc", dict(addr=addr)):
      yield Op(addr, l)

  def in_same_mod(self, addr0: int, addr1: int) -> bool:
    for _, in self.db.execute("select 1 from ops where addr=:addr0 and map_id=(select map_id from ops where addr=:addr1)", dict(addr0=addr0, addr1=addr1)):
      return True
    return False

  def methods_in_class(self, method_name: str, related_class_name: str) -> Iterator[int]:
    for addr, in self.db.execute('select low from map where method like :method_pat and class in (select class from class_rel where super like :class_pat or impl like :class_pat)', dict(class_pat=f'%{related_class_name}%', method_pat=f'%{method_name}%')):
      yield addr

  def related_classes(self, related_class_name: str) -> Iterator[int]:
    for addr, in self.db.execute('select low from map where class in (select class from class_rel where super regexp :pat or impl regexp :pat)', dict(pat=related_class_name)):
      yield addr

  def matches_in_method(self, addr: int, pattern: InvocationPattern) -> Iterator[Op]:
    for addr, l in self.db.execute('select addr, l from ops join (select low, high from ops join map on (map_id=id) where addr=:addr) on (addr between low and high) where l regexp :pat', dict(addr=addr, pat=f'^  ${pattern.insn} ${pattern.value}')):
      yield Op(addr, l)

  def methods_with_modifier(self, pattern: str) -> Iterator[Op]:
    for addr, l in self.db.execute('select addr, l from ops join map on (addr=low) where method is not null and l like :pat', dict(pat=f'% {pattern} %')):
      yield Op(addr, l)

  def classes_has_method_named(self, pattern: str) -> Iterator[Op]:
    for addr, l in self.db.execute('select addr, l from ops join map on (addr=low) where method is null and class in (select class from map where method regexp :pat)', dict(pat=pattern)):
      yield Op(addr, l)

  def classes_extends_has_method_named(self, method: str, extends: str) -> Iterator[Op]:
    for addr, l in self.db.execute('select addr, l from ops join map on (addr=low) where method is null and class in (select class from map join class_rel using (class) where method regexp :method and super regexp :extends)', dict(method=method, extends=extends)):
      yield Op(addr, l)

  def classes_implements_has_method_named(self, method: str, implements: str) -> Iterator[Op]:
    for addr, l in self.db.execute('select addr, l from ops join map on (addr=low) where method is null and class in (select class from map join class_rel using (class) where method regexp :method and impl regexp :implements)', dict(method=method, implements=implements)):
      yield Op(addr, l)

  def class_names(self, pat: str) -> Iterator[str]:
    for name, in self.db.execute('select class from map where method is null and class regexp :pat', dict(pat=pat)):
      yield name

  def body(self, class_name: str, method_name: Optional[str]) -> Iterator[Op]:
    stmt0 = 'select addr, l from ops join map on (addr between low and high) where method is null and class=:class_name'
    stmt1 = 'select addr, l from ops join map on (addr between low and high) where method=:method_name and class=:class_name'
    for addr, l in self.db.execute(stmt1 if method_name else stmt0, dict(class_name=class_name, method_name=method_name)):
      yield Op(addr, l)

  def call_add_batch(self, gen: Iterator[Call]) -> None:
    stmt0 = 'insert into ncalls (priv, cpp, target, path, sect, offs) values (:priv, :cpp, :target, :path, :sect, :offs)'
    self.db.executemany(stmt0, gen)

  def call_count(self) -> int:
    stmt0 = 'select count(1) from ncalls'
    for n, in self.db.execute(stmt0):
      return n # type:ignore[no-any-return]
    return 0

  def calls(self, priv: bool = False, api: bool = False) -> Iterator[Call]:
    stmt0 = 'select priv, cpp, target, path, sect, offs from ncalls'
    stmt1 = 'select priv, cpp, target, path, sect, offs from ncalls where priv=:is_priv'
    for priv, cpp, target, path, sect, offs in self.db.execute(stmt1 if (priv or api) else stmt0, dict(is_priv=priv)):
      yield dict(
        path=path,
        sect=sect,
        offs=offs,
        priv=priv,
        cpp=cpp,
        target=target,
      )
