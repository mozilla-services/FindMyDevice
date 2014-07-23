# Running updates

Yes, I will make this more seamless in the future.

For now, you only need to run "new" updates (although the sql should
prevent multiple modifications).

e.g.

```sh
$ psql --user=$USER --password --host=$HOST $DB < update_20140707.sql
```

will run the update for 20140707.sql, where:

- `$USER` is a placeholder for the `db.user` value defined in config.ini
- `$HOST` is a placeholder for the `db.host` value defined in config.ini
- `$DB` is a placeholder for the `db.db` value defined in config.ini

**Note:** When prompted for a password, use the value of `db.password` defined
in config.ini.

The output will indicate '1' for a successful execution or '0' if the
command was not run (error, or unneeded).
