--- ops
create table ops (addr integer primary key, l varchar not null, map_id integer not null);
create table map (id integer primary key, low integer not null, high integer not null, class varchar, method varchar);
create table class_rel (class varchar not null, super varchar, impl varchar);
create table xref_const (addr integer primary key, insn varchar not null, sym varchar not null);
create table xref_invoke (addr integer primary key, target integer, insn varchar not null, sym varchar not null);
create table xref_sput (addr integer primary key, insn varchar not null, sym varchar not null);
create table xref_iput (addr integer primary key, insn varchar not null, sym varchar not null);
create table ncalls (nr integer primary key, priv boolean not null, cpp boolean not null, target varchar not null, path varchar not null, sect varchar not null, offs integer not null);
create index idx_map_class on map (class);
create index idx_xref_invoke_target on xref_invoke (target);
