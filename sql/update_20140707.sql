create or replace function update_db() returns int language plpgsql as $$
DECLARE
    x int;
BEGIN
    select count(column_name) into x from information_schema.columns where table_name='position' and column_name='accuracy';
    if x = 0 then
        alter table position add column accuracy real;
        return 1;
    end if;
    return 0;
END;
$$;
select update_db()
