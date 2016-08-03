pragma journal_mode=wal;
begin exclusive;

drop view consts;
drop view invokes;
drop view method_ops;
drop view class_ops;
drop view class_methods;
drop view method_class;
drop table class_class_name;
drop table method_method_name;
drop table method_qualname;
drop view api_calls;
drop table api_calls_snap;
drop view method_callees;
drop table method_callees_snap;
drop view method_callgraphs;

-- extract constant point (thus register write)
create view consts as select * from op_vecs where t='id' and v like 'const%';

-- extract invocation points (thus register ref)
create view invokes as select * from op_vecs where (v like 'invoke%');

-- views
create view method_ops as select ops_method.method as method, ops.op as op, ops.t as t, ops.v as v from ops join ops_method using (op);
create view class_ops as select ops_class.class as class, ops.op as op, ops.t as t, ops.v as v from ops join ops_class using (op);
create view class_methods as select ops_class.class as class,ops_method.method as method from ops_class join ops_method on (ops_method.op=ops_method.method and ops_method.method=ops_class.op);
create view method_class as select A.method as method, B.class as class from (select distinct method from ops_method) as A join ops_class as B on (B.op=A.method);

-- concrete tables
create table class_class_name(class integer primary key, class_name varchar not null unique);
insert into class_class_name select op as class, coalesce(v9,v8,v7,v6,v5,v4,v3,v2,v1,v) as class_name from op_vecs where t='directive' and v='class';

create table method_method_name (method integer primary key, method_name varchar not null);
insert into method_method_name select method, (case when name='constructor' then '' else name end||sig) as method_name from (select method, (select v from ops where op=sigop) as sig, (select v from ops where op=sigop-1) as name from (select op as method, coalesce(op9,op8,op7,op6,op5,op4,op3,op2,op1,op) as sigop from op_vecs where t='directive' and v='method') as A) as AA;

create table method_qualname (method integer primary key, qualname varchar not null);
insert into method_qualname select method, (class_name||'->'||method_name) as qualname from class_methods join class_class_name using (class) join method_method_name using (method);
create index method_qualname_qualname on method_qualname(qualname);

-- API calls
create view api_calls as select invokes.op as op, ops_method.method as method, (case when invokes.t1='reflike' then invokes.v1 else invokes.v2 end) as qualname from ops_method join invokes using (op) left join method_qualname on ((case when invokes.t1='reflike' then invokes.v1 else invokes.v2 end)=qualname) where method_qualname.method is null;
create table api_calls_snap (op integer primary key, method integer not null, qualname varchar not null);
insert into api_calls_snap select * from api_calls;
create index api_calls_snap_method on api_calls_snap(method);

-- finds which op is calling given method
--select op_vecs.* from ops_p join (select op as p from ops where v like 'Landroid/util/Log;%') using (p) join op_vecs using (op);

-- extract call graph
create view method_callees as select invokes.op as op, ops_method.method as method, method_qualname.method as callee from ops_method join invokes using (op) join method_qualname on ((case when invokes.t1='reflike' then invokes.v1 else invokes.v2 end)=qualname);
create table method_callees_snap (op integer primary key, method integer not null, callee integer not null);
insert into method_callees_snap select * from method_callees;
create index method_callees_snap_method on method_callees_snap(method);

create view method_callgraphs as select distinct c1.method as method,c1.callee as callee1,c2.callee as callee2,c3.callee as callee3,c4.callee as callee4,c5.callee as callee5,c6.callee as callee6,c7.callee as callee7,c8.callee as callee8,c9.callee as callee9,ca.callee as calleea from method_callees_snap as c1 left join method_callees_snap as c2 on (c1.callee=c2.method) left join method_callees_snap as c3 on (c2.callee=c3.method) left join method_callees_snap as c4 on (c3.callee=c4.method) left join method_callees_snap as c5 on (c4.callee=c5.method) left join method_callees_snap as c6 on (c5.callee=c6.method) left join method_callees_snap as c7 on (c6.callee=c7.method) left join method_callees_snap as c8 on (c7.callee=c8.method) left join method_callees_snap as c9 on (c8.callee=c9.method) left join method_callees_snap as ca on (c9.callee=ca.method);

-- extract register write

create view op_reg_influences as select referer.op as op, referer.v as insn, ops_p.idx as idx, ops.v as reg from ops join ops_p on (ops.op=ops_p.p) join ops as referer on (referer.op=ops_p.op) where ops.t in ('reg', 'multireg');

-- extract register ref

commit;
