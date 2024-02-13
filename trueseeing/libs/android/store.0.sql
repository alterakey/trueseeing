begin exclusive;

--- ops
create table ops (op integer primary key, idx integer not null, t varchar not null, v varchar not null);
create table ops_method (op integer primary key, method integer not null);
create table ops_class (op integer primary key, class integer not null);

-- analytic reports
create table analysis_issues (issue integer primary key, sig varchar not null, title varchar not null, score float not null, cfd integer not null, info0 varchar not null, info1 varchar not null, info2 varchar not null, aff0 varchar not null, aff1 varchar not null, aff2 varchar not null, cvss varchar not null, summary varchar not null, descr varchar not null, ref varchar not null, sol varchar not null, unique (sig, title, score, cfd, info0, info1, info2, aff0, aff1, aff2));


commit;
