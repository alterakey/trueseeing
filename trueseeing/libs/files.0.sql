begin exclusive;

drop table if exists files;
drop table if exists patches;

create table files (path text not null unique, z boolean not null, blob bytes not null);
create table patches (path text not null unique, z boolean not null, blob bytes not null);

commit;
