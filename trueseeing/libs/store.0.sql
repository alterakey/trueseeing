pragma journal_mode=wal;
begin exclusive;

create table ops (op integer primary key, t varchar not null, v varchar not null);
create table ops_p (op integer not null, idx integer not null, p integer primary key);
create table ops_method (op integer primary key, method integer not null);
create table ops_class (op integer primary key, class integer not null);
create index ops_method_method on ops_method (method);
create index ops_class_class on ops_class (class);
create index ops_p_op on ops_p (op);

commit;
