create or replace function update_db() returns int language plpgsql as $$
DECLARE
   x int;
   t bool;
BEGIN
    t := false;
    select count(column_name) into x from information_schema.columns where table_name='deviceinfo' and column_name='accesstoken';
    IF x = 0 THEN
        alter table deviceinfo add column accesstoken varchar;
        t = t or true;
    END IF;
    select count(column_name) into x from information_schema.columns where table_name='usertodevicemap' and column_name='date';
    IF x = 0 THEN
        alter table usertodevicemap add column date timestamp;
        t = t or true;
    END IF;
    IF t then
        return 1;
    end if;
    return 0;
END;
$$;
select update_db();
