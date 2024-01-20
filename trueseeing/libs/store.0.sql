begin exclusive;

create table ops (op integer primary key, idx integer not null, t varchar not null, v varchar not null);
create table ops_method (op integer primary key, method integer not null);
create table ops_class (op integer primary key, class integer not null);

commit;
