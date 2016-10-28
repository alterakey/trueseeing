import re
import random
import hashlib
import os.path
import sqlite3
import itertools
import pkg_resources
import trueseeing.literalquery
import trueseeing.code.model

def _re_fn(expr, item):
  return re.compile(expr).search(item) is not None

class Store:
  def __init__(self, path, mode='r'):
    if mode in 'rw':
      self.path = os.path.join(path, 'store.db')
      with open(self.path, mode) as _:
        pass
      self.db = sqlite3.connect(self.path)
      self.db.create_function("REGEXP", 2, _re_fn)
      trueseeing.literalquery.Store(self.db).stage0()
      if mode == 'w':
        trueseeing.literalquery.Store(self.db).stage1()
    else:
      raise ArgumentError('mode: %s' % mode)

  def __enter__(self):
    self.db.__enter__()
    return self

  def __exit__(self, exc_type, exc_value, traceback):
    self.db.__exit__(exc_type, exc_value, traceback)

  def op_finalize(self):
    trueseeing.literalquery.Store(self.db).stage2()

  def op_get(self, k):
    for t,v in self.db.execute('select t,v from ops where id=?', (k)):
      return Token(t, v)

  def op_append(self, op):
    unused_id = None
    for r in self.db.execute('select max(op) from ops'):
      if r[0] is not None:
        unused_id = r[0] + 1
      else:
        unused_id = 1
    vec = tuple([op] + op.p)
    for t, idx in zip(vec, range(len(vec))):
      t._idx = idx
      t._id = unused_id + idx
    self.db.executemany('insert into ops(op,t,v) values (?,?,?)', ((t._id, t.t, t.v) for t in vec))
    self.db.executemany('insert into ops_p(op, idx, p) values (?,?,?)', ((op._id, t._idx, t._id) for t in vec))

  def op_mark_method(self, ops, method):
    self.db.executemany('insert into ops_method(op,method) values (?,?)', ((str(o._id), str(method._id)) for o in ops))

  def op_mark_class(self, ops, class_, ignore_dupes=False):
    if not ignore_dupes:
      self.db.executemany('insert into ops_class(op,class) values (?,?)', ((str(o._id), str(class_._id)) for o in ops))
    else:
      self.db.executemany('insert or ignore into ops_class(op,class) values (?,?)', ((str(o._id), str(class_._id)) for o in ops))

  def query(self):
    return Query(self)

class Query:
  def __init__(self, store):
    self.db = store.db

  def reversed_insns_in_method(self, from_):
    for r in self.db.execute('select op as _0, t as _1, v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from op_vecs where op in (select op from ops_method where op<=(select op from ops_p where p=:from_op) and method=(select method from ops_method where op=(select op from ops_p where p=:from_op))) order by op desc', dict(from_op=from_._id)):
      yield trueseeing.code.model.Op(r[1], r[2], [trueseeing.code.model.Op(o[1], o[2], [], id_=o[0]) for o in (r[x:x+3] for x in range(3,30,3)) if o[0] is not None], id_=r[0])

  @staticmethod
  def _cond_as_sql(param, t, v):
    cond = dict(cond='1')
    if t is not None or v is not None:
      cond.update(dict(cond=' and '.join(['t=:t' if t is not None else '1', 'v like :v' if v is not None else '1'])))
      param.update({p:q for p,q in dict(t=t, v=v).items() if q is not None})
    return cond, param

  def find_recent_in_method(self, from_, t, v):
    cond, param = self._cond_as_sql(dict(from_op=from_._id), t, v)
    for r in self.db.execute('select op as _0, t as _1, v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from op_vecs where op in (select op from ops_method where op<=(select op from ops_p where p=:from_op) and method=(select method from ops_method where op=(select op from ops_p where p=:from_op))) and (%(cond)s) order by op desc' % cond, param):
      yield trueseeing.code.model.Op(r[1], r[2], [trueseeing.code.model.Op(o[1], o[2], [], id_=o[0]) for o in (r[x:x+3] for x in range(3,30,3)) if o[0] is not None], id_=r[0])

  def ops(self):
    for r in self.db.execute('select op as _0, t as _1, v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from op_vecs'):
      yield trueseeing.code.model.Op(r[1], r[2], [trueseeing.code.model.Op(o[1], o[2], [], id_=o[0]) for o in (r[x:x+3] for x in range(3,30,3)) if o[0] is not None], id_=r[0])

  def invocations(self, pattern):
    for r in self.db.execute('select op as _0, t as _1, v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from (select ops.op from ops join ops_p on (ops_p.op=ops.op and idx=2) join ops as target on (ops_p.p=target.op) where ops.t=\'id\' and ops.v like \'%(insn)s%%\'%(regexp)s) as A join op_vecs using (op)' % dict(insn=pattern.insn, regexp=' and target.v regexp \'%(expr)s\'' % dict(expr=pattern.value))):
      yield trueseeing.code.model.Op(r[1], r[2], [trueseeing.code.model.Op(o[1], o[2], [], id_=o[0]) for o in (r[x:x+3] for x in range(3,30,3)) if o[0] is not None], id_=r[0])

  def classes_has_method_named(self, pattern):
    for r in self.db.execute('select op as _0, t as _1, v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from op_vecs join ops_method using (op) where op in (select class from methods_class join method_method_name using (method) where method_name regexp \'%(expr)s\')' % dict(expr=pattern)):
      yield trueseeing.code.model.Op(r[1], r[2], [trueseeing.code.model.Op(o[1], o[2], [], id_=o[0]) for o in (r[x:x+3] for x in range(3,30,3)) if o[0] is not None], id_=r[0])

  def classes_extends_has_method_named(self, method, extends):
    for r in self.db.execute('select op as _0, t as _1, v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from op_vecs where op in (select class from classes_extends_name join methods_class using (class) join method_method_name using (method) where method_name regexp \'%(expr1)s\' and extends_name regexp \'%(expr2)s\')' % dict(expr1=method, expr2=extends)):
      yield trueseeing.code.model.Op(r[1], r[2], [trueseeing.code.model.Op(o[1], o[2], [], id_=o[0]) for o in (r[x:x+3] for x in range(3,30,3)) if o[0] is not None], id_=r[0])

  def classes_implements_has_method_named(self, method, implements):
    for r in self.db.execute('select op as _0, t as _1, v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from op_vecs where op in (select class from classes_implements_name join methods_class using (class) join method_method_name using (method) where method_name regexp \'%(expr1)s\' and implements_name regexp \'%(expr2)s\')' % dict(expr1=method, expr2=implements)):
      yield trueseeing.code.model.Op(r[1], r[2], [trueseeing.code.model.Op(o[1], o[2], [], id_=o[0]) for o in (r[x:x+3] for x in range(3,30,3)) if o[0] is not None], id_=r[0])

  def qualname_of(self, op):
    for r in self.db.execute('select qualname from method_qualname join ops_method using (method) where op=:op', dict(op=op._id)):
      return r[0]

  def callers_of(self, op):
    for r in self.db.execute('select op as _0, t as _1, v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from (select ops.op from ops join ops_p on (ops_p.op=ops.op and idx=2) join ops as target on (ops_p.p=target.op) where ops.t=\'id\' and ops.v like \'%(insn)s%%\'%(regexp)s) as A join op_vecs using (op)' % dict(insn=pattern.insn, regexp=' and target.v regexp \'%(expr)s\'' % dict(expr=pattern.value))):
    for r in (x for x in itertools.chain(*(c.ops for c in method.class_.global_.classes)) if x.t == 'id' and 'invoke' in x.v):
      try:
        ref = r.p[1].v
      except IndexError:
        ref = r.p[0].v
      if method.qualified_name() in ref:
        yield r
    pass

import logging
log = logging.getLogger(__name__)

class DataFlows2:
  class NoSuchValueError(Exception):
    pass

  class RegisterDecodeError(Exception):
    pass

  @staticmethod
  def likely_calling_in(store, ops):
    pass

  @staticmethod
  def into(store, o):
    return DataFlows2.analyze(store, o)

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
      raise DataFlows2.RegisterDecodeError("unknown type of reference: %s, %s" % (ref.t, ref.v))

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
    graph = DataFlows2.analyze(store, invokation_op)
    reg = DataFlows2.decoded_registers_of(invokation_op.p[0], type_=list)[index + (0 if invokation_op.v.endswith('-static') else 1)]
    arg = graph[invokation_op][reg]
    try:
      if arg.t == 'id' and arg.v.startswith('const'):
        return arg.p[1].v
      else:
        raise DataFlows2.NoSuchValueError('not a compile-time constant: %r' % arg)
    except AttributeError:
      raise DataFlows2.NoSuchValueError('not a compile-time constant: %r' % arg)

  @staticmethod
  def walk_dict_values(d):
    try:
      for v in d.values():
        yield from DataFlows2.walk_dict_values(v)
    except AttributeError:
      yield d

  @staticmethod
  def solved_possible_constant_data_in_invocation(store, invokation_op, index):
    assert invokation_op.t == 'id' and invokation_op.v.startswith('invoke')
    graph = DataFlows2.analyze(store, invokation_op)
    reg = DataFlows2.decoded_registers_of(invokation_op.p[0], type_=list)[index + (0 if invokation_op.v.endswith('-static') else 1)]
    return {x.p[1].v for x in DataFlows2.walk_dict_values(graph[invokation_op][reg]) if x is not None and x.t == 'id' and x.v.startswith('const')}

  @staticmethod
  def solved_typeset_in_invocation(store, invokation_op, index):
    assert invokation_op.t == 'id' and invokation_op.v.startswith('invoke')
    graph = DataFlows2.analyze(store, invokation_op)
    reg = DataFlows2.decoded_registers_of(invokation_op.p[0], type_=list)[index + (0 if invokation_op.v.endswith('-static') else 1)]
    arg = graph[invokation_op][reg]
    pprint.pprint(graph)
    raise Exception('breakpoint')

  @staticmethod
  def analyze(store, op):
    if op is not None and op.t == 'id':
      if any(op.v.startswith(x) for x in ['const','new-','move-exception']):
        return op
      elif op.v in ['move', 'array-length']:
        return {op:{k:DataFlows2.analyze(store, DataFlows2.analyze_recent_load_of(store, op, k)) for k in DataFlows2.decoded_registers_of(op.p[1])}}
      elif any(op.v.startswith(x) for x in ['aget-']):
        assert len(op.p) == 3
        return {op:{k:DataFlows2.analyze(store, DataFlows2.analyze_recent_array_load_of(store, op, k)) for k in (DataFlows2.decoded_registers_of(op.p[1]) | DataFlows2.decoded_registers_of(op.p[2]))}}
      elif any(op.v.startswith(x) for x in ['sget-']):
        assert len(op.p) == 2
        return {op:{k:DataFlows2.analyze(store, DataFlows2.analyze_recent_static_load_of(store, op)) for k in DataFlows2.decoded_registers_of(op.p[0])}}
      elif any(op.v.startswith(x) for x in ['iget-']):
        assert len(op.p) == 3
        return {op:{k:DataFlows2.analyze(store, DataFlows2.analyze_recent_instance_load_of(store, op)) for k in DataFlows2.decoded_registers_of(op.p[0])}}
      elif op.v.startswith('move-result'):
        return DataFlows2.analyze(store, DataFlows2.analyze_recent_invocation(store, op))
      else:
        try:
          return {op:{k:DataFlows2.analyze(store, DataFlows2.analyze_recent_load_of(store, op, k)) for k in DataFlows2.decoded_registers_of(op.p[0])}}
        except DataFlows2.RegisterDecodeError:
          return None

  @staticmethod
  def analyze_recent_static_load_of(store, op):
    assert op.t == 'id' and any(op.v.startswith(x) for x in ['sget-'])
    target = op.p[1].v
    for o in itertools.chain(DataFlows2.looking_behind_from(op), store.query().ops()):
      if o.t == 'id' and o.v.startswith('sput-'):
        if o.p[1].v == target:
          return o
    else:
      if op.p[1].v.startswith('Ljava/lang/'):
        return None
      else:
        raise Exception('failed static trace of: %r' % op)


  @staticmethod
  def analyze_load(store, op):
    if op.t == 'id':
      if any(op.v.startswith(x) for x in ['const','new-','move','array-length','aget-','sget-','iget-']):
        return DataFlows2.decoded_registers_of(op.p[0])
      elif any(op.v.startswith(x) for x in ['invoke-direct', 'invoke-virtual', 'invoke-interface']):
        # Imply modification of "this"
        return frozenset(DataFlows2.decoded_registers_of(op.p[0], type_=list)[:1])
      else:
        return frozenset()

  @staticmethod
  def analyze_recent_load_of(store, from_, reg):
    if reg.startswith('p'):
      index = int(reg.replace('p', ''))
      for caller in store.query().callers_of(from_.method_):
        caller_reg = DataFlows2.decoded_registers_of(caller.p[0], type_=list)[index]
        log.debug("analyze_recent_load_of: TBD: retrace: %s -> %s -> %r (in %r)" % (reg, caller_reg, caller, caller.method_))
      return None
    for o in DataFlows2.looking_behind_from(store, from_):
      if o.t == 'id':
        if reg in DataFlows2.analyze_load(o):
          return o

  @staticmethod
  def analyze_recent_array_load_of(store, from_, reg):
    return DataFlows2.analyze_recent_load_of(store, from_, reg)

  @staticmethod
  def analyze_recent_instance_load_of(store, op):
    assert len(op.p) == 3
    log.debug("analyze_recent_instance_load_of: TBD: instansic trace of %s (%s)" % (op.p[1], op.p[2]))
    return None

  @staticmethod
  def analyze_recent_invocation(store, from_):
    for o in DataFlows2.looking_behind_from(store, from_):
      if o.t == 'id' and o.v.startswith('invoke'):
        return o
