DECLARE
   x integer
BEGIN
    select count(column_name) into x from information_schema.columns where table_name='deviceinfo' and column_name='accesstoken';
    IF x == 0 THEN
        alter table deviceinfo add column accesstoken varchar;
    END IF;
    select count(column_name) into x from information_schema.columns where table_name='usertodevicemap' and column_name='date';
    IF x == 0 THEN
        alter table usertodevicemap add column date timestamp;
    END IF;
END;
