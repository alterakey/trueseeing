begin exclusive;

--- ops
create table ops (op integer primary key, idx integer not null, t varchar not null, v varchar not null);
create table ops_method (op integer primary key, method integer not null);
create table ops_class (op integer primary key, class integer not null);

-- analytic reports
create table analysis_issues (issue integer primary key, sig varchar not null, summary varchar not null, synopsis varchar not null, description varchar not null, seealso varchar not null, solution varchar not null, info1 varchar not null, info2 varchar not null, info3 varchar not null, confidence integer not null, cvss3_score float not null, cvss3_vector varchar not null, source varchar not null, row varchar not null, col varchar not null, unique (sig, summary, info1, info2, info3, cvss3_score, confidence, source, row, col));


commit;
