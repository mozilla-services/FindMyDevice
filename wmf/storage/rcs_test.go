/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package storage

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/mozilla-services/FindMyDevice/util"
	"github.com/rafrombrc/gospec/src/gospec"
	. "github.com/rafrombrc/gospec/src/gospec"
)

func verify_templates(patch_dir string) (err error) {
	files := []string{"prev.txt", "upgrade.sql", "downgrade.sql.orig"}
	for _, fname := range files {
		filename := filepath.Join(patch_dir, fname)
		if _, err := os.Stat(filename); os.IsNotExist(err) {
			return fmt.Errorf("no such file or directory: %s", filename)
		}
	}
	return nil
}

func RcsSpec(c gospec.Context) {

	c.Specify("Create an initial version", func() {
		var patch_dir string
		rcs, err := initDB()
		defer func() {
			c.Expect(rcs.Close(), IsNil)
		}()
		c.Expect(err, IsNil)

		patch_root, err := ioutil.TempDir("", "")
		c.Expect(err, IsNil)
		defer func() {
			os.RemoveAll(patch_root)
		}()

		prev, rev, err := rcs.CreateNextRev(patch_root, "initial commit")
		c.Expect(err, IsNil)
		c.Expect(prev, Equals, "")
		c.Expect(rev, Not(Equals), "")

		patch_dir, err = GetPatchDirectory(patch_root, rev)
		c.Expect(err, IsNil)
		c.Expect(verify_templates(patch_dir), IsNil)
	})

	c.Specify("create 2 revisions", func() {
		var patch_dir string
		var new_prev, new_rev string
		var prev, rev string

		rcs, err := initDB()
		defer func() {
			c.Expect(rcs.Close(), IsNil)
		}()
		c.Expect(err, IsNil)
		patch_root, err := ioutil.TempDir("", "")
		c.Expect(err, IsNil)
		defer func() {
			os.RemoveAll(patch_root)
		}()

		prev, rev, err = rcs.CreateNextRev(patch_root, "initial commit")
		c.Expect(err, IsNil)
		c.Expect(prev, Equals, "")
		c.Expect(rev, Not(Equals), "")

		patch_dir, err = GetPatchDirectory(patch_root, rev)
		c.Expect(err, IsNil)
		c.Expect(verify_templates(patch_dir), IsNil)

		// Check that the last revision is available
		var result string
		result, err = rcs.FindLastVersion(patch_root)
		c.Expect(err, IsNil)
		c.Expect(result, Equals, rev)

		new_prev, new_rev, err = rcs.CreateNextRev(patch_root, "new commit")
		c.Expect(err, IsNil)

		// Check that history is preserved
		c.Expect(new_prev, Equals, rev)
		c.Expect(new_rev, Not(Equals), "")
	})

	c.Specify("database can be upgraded", func() {

		patch_root, err := ioutil.TempDir("", "")
		fmt.Printf("Patchroot: [%v]\n", patch_root)
		c.Expect(err, IsNil)
		defer func() {
			os.RemoveAll(patch_root)
		}()

		// create the test database
		rcs, err := initDB()
		defer func() {
			c.Expect(rcs.Close(), IsNil)
		}()
		c.Expect(err, IsNil)

		var rev string
		var patch_dir string
		var upgrade_sql string

		// write a change into update.sql
		_, rev, _ = rcs.CreateNextRev(patch_root, "initial commit")
		patch_dir, _ = GetPatchDirectory(patch_root, rev)
		upgrade_sql = filepath.Join(patch_dir, "upgrade.sql")
		simplewrite(upgrade_sql, "create table public.foo (col_a integer);\n")

		// alter the table now
		var prev string
		prev, rev, _ = rcs.CreateNextRev(patch_root, "alter table")
		fmt.Printf("Prev : [%v]   Curr: [%v]\n", prev, rev)
		patch_dir, _ = GetPatchDirectory(patch_root, rev)
		upgrade_sql = filepath.Join(patch_dir, "upgrade.sql")
		sql_txt := `
				-- A comment

				alter table foo add column col_b integer;
				alter table foo add column col_c varchar(40);
				-- more comments
				create table public.bar (col_a varchar(20));
						`
		simplewrite(upgrade_sql, sql_txt)

		// Run upgrade script
		err = rcs.Upgrade(patch_root, true)
		c.Expect(err, IsNil)

		// test that schema change was made
		_, err = rcs.Db.Exec("select col_b from foo")
		c.Expect(err, IsNil)

		_, err = rcs.Db.Exec("select col_c from foo")
		c.Expect(err, IsNil)

		_, err = rcs.Db.Exec("select col_a from bar")
		c.Expect(err, IsNil)

		_, err = rcs.Db.Exec("select col_a from baz")
		c.Expect(err, Not(IsNil))

		// Check the version code
		db_ver, err := rcs.CurrentDBVersion()
		c.Expect(db_ver, Equals, rev)

	})

	c.Specify("database can be downgrade fails for invalid revisions", func() {
		var patch_dir string
		var rev string

		rcs, err := initDB()
		defer func() {
			c.Expect(rcs.Close(), IsNil)
		}()
		c.Expect(err, IsNil)
		patch_root, err := ioutil.TempDir("", "")
		c.Expect(err, IsNil)
		defer func() {
			os.RemoveAll(patch_root)
		}()

		_, rev, _ = rcs.CreateNextRev(patch_root, "initial commit")
		patch_dir, _ = GetPatchDirectory(patch_root, rev)
		simplewrite(filepath.Join(patch_dir, "upgrade.sql"), "create table public.foo (col_a integer);\n")
		_, rev, _ = rcs.CreateNextRev(patch_root, "new commit")
		patch_dir, _ = GetPatchDirectory(patch_root, rev)
		simplewrite(filepath.Join(patch_dir, "upgrade.sql"), "create table public.bar (col_a integer);\n")
		err = rcs.Upgrade(patch_root, true)
		c.Expect(err, IsNil)

		err = rcs.Downgrade(patch_root, "boofdsa")
		c.Expect(err.Error(), Equals, "No previous version [boofdsa] can be found")
	})

	c.Specify("database can be downgraded", func() {
		patch_root, err := ioutil.TempDir("", "")
		fmt.Printf("Patchroot: [%v]\n", patch_root)
		c.Expect(err, IsNil)
		defer func() {
			os.RemoveAll(patch_root)
		}()

		// create the test database
		rcs, err := initDB()
		defer func() {
			c.Expect(rcs.Close(), IsNil)
		}()
		c.Expect(err, IsNil)

		var rev string
		var patch_dir string
		var upgrade_sql string
		var init_rev string

		// write a change into update.sql
		_, rev, _ = rcs.CreateNextRev(patch_root, "initial commit")
		// keep the initial revision
		init_rev = rev
		patch_dir, _ = GetPatchDirectory(patch_root, rev)
		upgrade_sql = filepath.Join(patch_dir, "upgrade.sql")
		simplewrite(upgrade_sql, "create table public.foo (col_a integer);\n")

		// alter the table now
		var prev string
		prev, rev, _ = rcs.CreateNextRev(patch_root, "alter table")
		fmt.Printf("Prev : [%v]   Curr: [%v]\n", prev, rev)
		patch_dir, _ = GetPatchDirectory(patch_root, rev)
		upgrade_sql = filepath.Join(patch_dir, "upgrade.sql")
		sql_txt := `
				-- A comment

				alter table foo add column col_b integer;
				alter table foo add column col_c varchar(40);
				-- more comments
				create table public.bar (col_a varchar(20));
						`
		simplewrite(upgrade_sql, sql_txt)

		sql_txt = `
				alter table foo drop column col_b;
						`
		simplewrite(filepath.Join(patch_dir, "downgrade.sql"), sql_txt)

		// Run upgrade script
		err = rcs.Upgrade(patch_root, true)
		c.Expect(err, IsNil)

		// Downgrade one level
		err = rcs.Downgrade(patch_root, init_rev)
		c.Expect(err, IsNil)

		// Check the version code
		db_ver, err := rcs.CurrentDBVersion()
		c.Expect(db_ver, Not(Equals), rev)
		c.Expect(db_ver, Equals, init_rev)

	})

	c.Specify("DDL failures are safely rolled back", func() {
		patch_root, err := ioutil.TempDir("", "")
		fmt.Printf("Patchroot: [%v]\n", patch_root)
		c.Expect(err, IsNil)
		defer func() {
			os.RemoveAll(patch_root)
		}()

		// create the test database
		rcs, err := initDB()
		defer func() {
			c.Expect(rcs.Close(), IsNil)
		}()
		c.Expect(err, IsNil)

		var init_rev string
		var rev string
		var patch_dir string
		var upgrade_sql string

		// write a change into update.sql
		_, init_rev, _ = rcs.CreateNextRev(patch_root, "initial commit")
		patch_dir, _ = GetPatchDirectory(patch_root, init_rev)
		upgrade_sql = filepath.Join(patch_dir, "upgrade.sql")
		simplewrite(upgrade_sql, "create table public.foo (col_a integer);\n")

		// alter the table now
		var prev string
		prev, rev, _ = rcs.CreateNextRev(patch_root, "alter table")
		fmt.Printf("Prev : [%v]   Curr: [%v]\n", prev, rev)
		patch_dir, _ = GetPatchDirectory(patch_root, rev)
		upgrade_sql = filepath.Join(patch_dir, "upgrade.sql")
		sql_txt := `
			-- A comment

			alter table foo add column col_b integer;
			alter table foo blarh add column col_c varchar(40);
					`
		simplewrite(upgrade_sql, sql_txt)

		// Run upgrade script
		err = rcs.Upgrade(patch_root, true)
		c.Expect(err, Not(IsNil))

		// verify that the foo table is unaltered
		_, err = rcs.Db.Exec("select col_a from foo")
		c.Expect(err, IsNil)

		_, err = rcs.Db.Exec("select col_b from foo")
		c.Expect(err, Not(IsNil))

		// verify that the version code sits at init_rev
		db_ver, err := rcs.CurrentDBVersion()
		c.Expect(db_ver, Equals, init_rev)

	})
}

func initDB() (rcs *DBRcs, err error) {
	db_config := `#Database credentials
db.user=postgres
db.password=test
db.host=localhost
db.db=findmydevice_test
`
	simplewrite("config.test.ini", db_config)
	defer func() {
		os.Remove("config.test.ini")
	}()

	config, _ := util.ReadMzConfig("config.test.ini")

	rcs = new(DBRcs)
	if err = rcs.Init(config); err != nil {
		fmt.Printf("Error running Init on rcs: [%v]\n", err)
		return nil, err
	}

	// Reset the public schema in the test database
	if _, err = rcs.Db.Exec("drop schema if exists public cascade;"); err != nil {
		fmt.Printf("Error droping public schema: [%v]\n", err)
		return nil, err
	}
	if _, err = rcs.Db.Exec("create schema if not exists public;"); err != nil {
		fmt.Printf("Error creating public schema: [%v]\n", err)
		return nil, err
	}
	rcs.InitVersioning()
	return rcs, nil
}
