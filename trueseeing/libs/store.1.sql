begin exclusive;

-- indices
create index ops_method_method on ops_method (method);
create index ops_class_class on ops_class (class);
create index ops_p_op on ops_p (op);

-- vector view
create view op_vecs as
  select
    p0.op as op, o0.t as t, o0.v as v,
    p1.p as op1, o1.t as t1, o1.v as v1,
    p2.p as op2, o2.t as t2, o2.v as v2,
    p3.p as op3, o3.t as t3, o3.v as v3,
    p4.p as op4, o4.t as t4, o4.v as v4,
    p5.p as op5, o5.t as t5, o5.v as v5,
    p6.p as op6, o6.t as t6, o6.v as v6,
    p7.p as op7, o7.t as t7, o7.v as v7,
    p8.p as op8, o8.t as t8, o8.v as v8,
    p9.p as op9, o9.t as t9, o9.v as v9
    from
      ops_p as p0 join ops as o0 on (p0.idx=0 and o0.op=p0.p)
      left join ops_p as p1 on (p0.op=p1.op and p1.idx=1) left join ops as o1 on (o1.op=p1.p)
      left join ops_p as p2 on (p0.op=p2.op and p2.idx=2) left join ops as o2 on (o2.op=p2.p)
      left join ops_p as p3 on (p0.op=p3.op and p3.idx=3) left join ops as o3 on (o3.op=p3.p)
      left join ops_p as p4 on (p0.op=p4.op and p4.idx=4) left join ops as o4 on (o4.op=p4.p)
      left join ops_p as p5 on (p0.op=p5.op and p5.idx=5) left join ops as o5 on (o5.op=p5.p)
      left join ops_p as p6 on (p0.op=p6.op and p6.idx=6) left join ops as o6 on (o6.op=p6.p)
      left join ops_p as p7 on (p0.op=p7.op and p7.idx=7) left join ops as o7 on (o7.op=p7.p)
      left join ops_p as p8 on (p0.op=p8.op and p8.idx=8) left join ops as o8 on (o8.op=p8.p)
      left join ops_p as p9 on (p0.op=p9.op and p9.idx=9) left join ops as o9 on (o9.op=p9.p);

-- views
create table methods_class(method integer primary key, class integer not null) without rowid;
insert into methods_class select ops_method.method as method,ops_class.class as class from ops_method join ops_class using (op) group by method;
create index methods_class_class on methods_class (class);

-- concrete tables
create table class_class_name(class integer primary key, class_name varchar not null unique) without rowid;
insert into class_class_name select op as class, coalesce(v9,v8,v7,v6,v5,v4,v3,v2,v1,v) as class_name from op_vecs where t='directive' and v='class';

create table method_method_name (method integer primary key, method_name varchar not null) without rowid;
insert into method_method_name select method, (case when name='constructor' then '' else name end||sig) as method_name from (select method, (select v from ops where op=sigop) as sig, (select v from ops where op=sigop-1) as name from (select op as method, coalesce(op9,op8,op7,op6,op5,op4,op3,op2,op1,op) as sigop from op_vecs where t='directive' and v='method') as A) as AA;

create table method_qualname (method integer primary key, qualname varchar not null) without rowid;
insert into method_qualname select method, (class_name||'->'||method_name) as qualname from methods_class join class_class_name using (class) join method_method_name using (method);
create index method_qualname_qualname on method_qualname(qualname);

create table classes_extends_name (class integer primary key, extends_name varchar not null) without rowid;
insert into classes_extends_name select C.class as class,B.v as extends_name from (select op from ops where t='directive' and v='super') as A join ops as B on (B.op=A.op+1) join ops_class as C on (A.op=C.op);

create table classes_implements_name (class integer not null, implements_name varchar not null);
insert into classes_implements_name select C.class as class,B.v as implements_name from (select op from ops where t='directive' and v='implements') as A join ops as B on (B.op=A.op+1) join ops_class as C on (A.op=C.op);

-- analytic interests
create table interests_invokes (op integer primary key, v varchar not null, target varchar not null) without rowid;
insert into interests_invokes select op, v, coalesce(v2,v1) as target from op_vecs where t='id' and v like 'invoke%';
create index interests_invokes_target on interests_invokes (target);

create table interests_consts (op integer primary key, v varchar not null, target varchar not null) without rowid;
insert into interests_consts select op, v, v2 as target from op_vecs where t='id' and v like 'const%';

create table interests_sputs (op integer primary key, v varchar not null, target varchar not null) without rowid;
insert into interests_sputs select op, v, v1 as target from op_vecs where t='id' and v like 'sput%';
create index interests_sputs_target on interests_sputs (target);

create table interests_iputs (op integer primary key, v varchar not null, target varchar not null) without rowid;
insert into interests_iputs select op, v, v3 as target from op_vecs where t='id' and v like 'iput%';
create index interests_iputs_target on interests_iputs (target);

-- analytic reports
create table analysis_issues (detector varchar not null, summary varchar not null, synopsis varchar, description varchar, seealso varchar, solution varchar, info1 varchar, info2 varchar, info3 varchar, confidence varchar not null, cvss3_score float not null, cvss3_vector varchar not null, source varchar, row varchar, col varchar);

analyze;

commit;
