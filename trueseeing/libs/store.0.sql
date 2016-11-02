begin exclusive;

create table ops (op integer primary key, t varchar not null, v varchar not null) without rowid;
create table ops_p (op integer not null, idx integer not null, p integer primary key) without rowid;
create table ops_method (op integer primary key, method integer not null) without rowid;
create table ops_class (op integer primary key, class integer not null) without rowid;

commit;
