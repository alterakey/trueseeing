drop table if exists files;
create table files(path text not null unique, blob bytes not null);
