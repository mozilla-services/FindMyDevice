DECLARE
    x integer
BEGIN
    select count(column_name) into x from information_schema.columns where table_name='pendingcommands' and column_name='type';
    if x == 0 then
        alter table pendingcommands add column type varchar;
    end if;
END;
