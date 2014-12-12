/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
This file manages schema modification.

There are a couple pieces to this:

1  Each schema modification is in a self contained directory with the a directory name
2. Each modification must contain an 'upgrade.sql'
3. Each modification *may* contain a 'downgrade.sql' script
4. Failure to include a downgrade script means we cannot downgrade past a particular version.

Every revision is stored in a directory named:

	rev.<SHA1_HEX>.<description>

	Each directory contains:
		(mandatory) prev.txt		-- contains the revision code for the previous patch
		(mandatory) upgrade.sql		-- upgrade sql
		(optional) downgrade.sql	-- downgrade sql

*/
package storage

import (
	"crypto/sha1"
	"database/sql"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/mozilla-services/FindMyDevice/util"
)

type DBRcs struct {
	Db *sql.DB

	revisions []*versionNode
}

type versionNode struct {
	version string
	prev    string
}

func simplewrite(fpath, content string) (err error) {
	intPerm, _ := strconv.ParseInt("777", 8, 32)
	return ioutil.WriteFile(fpath, []byte(content), os.FileMode(intPerm))
}

func (self *DBRcs) Close() (err error) {
	return self.Db.Close()
}

func (self *DBRcs) Init(config *util.MzConfig) (err error) {

	dsn := fmt.Sprintf("user=%s password=%s host=%s dbname=%s sslmode=%s",
		config.Get("db.user", "user"),
		config.Get("db.password", "password"),
		config.Get("db.host", "localhost"),
		config.Get("db.db", "postgres"),
		config.Get("db.sslmode", "disable"))

	if self.Db, err = sql.Open("postgres", dsn); err != nil {
		return err
	}

	if _, err = self.Db.Exec("set search_path to public"); err != nil {
		return err
	}

	self.Db.SetMaxIdleConns(100)
	if err = self.Db.Ping(); err != nil {
		return err
	}

	if err = self.InitVersioning(); err != nil {
		return err
	}

	return err
}

func (self *DBRcs) Upgrade(patch_root string, verbose bool) (err error) {
	// 1. Read the version file passed in.
	// 2. Verify the previous version exists and matches the *current*
	//    version of the database.
	// 3. Start transactional schema upgrade
	// 4. Update version code in schema
	// 5. Rollback on failure, commit if no errors

	var curr_db_ver string
	var curr_patch_dir string
	var node *versionNode
	var sql_cmd string
	var txn *sql.Tx
	var upgrade_bytes []byte

	if err = self.ComputeHistory(patch_root); err != nil {
		return err
	}

	if curr_db_ver, err = self.CurrentDBVersion(); err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("No version code has been set yet.  You need to initialize the versioning system.")
		}
		return err
	}

	// walk the nodes from back to front
	for i := len(self.revisions) - 1; i >= 0; i-- {
		node = self.revisions[i]
		// Process this node
		curr_patch_dir, err = GetPatchDirectory(patch_root, node.version)
		if node.prev == curr_db_ver {
			upgrade_sql := filepath.Join(curr_patch_dir, "upgrade.sql")
			fmt.Printf("Reading from :[%v]\n", upgrade_sql)
			upgrade_bytes, err = ioutil.ReadFile(upgrade_sql)

			sql_cmd = string(upgrade_bytes)
			fmt.Printf("Attempting SQL is: [%v]\n", sql_cmd)
			txn, err = self.Db.Begin()
			if _, err = txn.Exec(sql_cmd); err != nil {
				fmt.Printf("Failed to execute: [%s]\n", sql_cmd)
				txn.Rollback()
				return err
			}

			// Roll the version forward
			_, err = txn.Exec("update meta set value = $1 where key = 'db.hash';", node.version)
			if err != nil {
				txn.Rollback()
				return err
			}
			fmt.Printf("Version switched from : [%v]\n", curr_db_ver)
			curr_db_ver = node.version
			fmt.Printf("Version switched to   : [%v]\n", curr_db_ver)
			txn.Commit()
			fmt.Printf("Success!  Executed [%v]\n", sql_cmd)
		}
	}
	return err
}

func (self *DBRcs) CurrentDBVersion() (db_ver string, err error) {
	/*
		Fetch the current database hash
	*/
	err = self.Db.QueryRow("select value from meta where key = 'db.hash';").Scan(&db_ver)
	return db_ver, err
}

func (self *DBRcs) InitVersioning() (err error) {
	// Stamp the database with a blank version code immediately after
	// the database has been created.

	var db_ver string
	_, err = self.Db.Exec("create table if not exists meta (key varchar, value varchar);")
	if err != nil {
		fmt.Printf("Got an error with create meta table: [%v]\n", err)
		return err
	}

	err = self.Db.QueryRow("select value from meta where key = 'db.hash';").Scan(&db_ver)
	if err == nil {
		return nil
	}
	if err == sql.ErrNoRows {
		_, err = self.Db.Exec("insert into meta (key, value) values ('db.hash', '');")
	}
	return err
}

func (self *DBRcs) Downgrade(patch_root, version string) (err error) {
	var curr_db_ver string
	var curr_patch_dir string
	var downgrade_bytes []byte
	var found_head_version bool
	var sql_cmd string
	var txn *sql.Tx
	var valid_version bool

	if err = self.ComputeHistory(patch_root); err != nil {
		return err
	}
	if curr_db_ver, err = self.CurrentDBVersion(); err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("No version code has been set yet.  You need to initialize the versioning system.")
		}
		return err
	}

	// Check that we've got the version somewhere in the previous
	// history
	for _, node := range self.revisions {
		if !found_head_version {
			if node.version == curr_db_ver {
				found_head_version = true
			} else {
				continue
			}
		}
		if node.prev == version {
			valid_version = true
			break
		}
	}
	if !valid_version {
		return fmt.Errorf("No previous version [%v] can be found", version)
	}

	fmt.Printf("Processing downgrade from [%s] to [%s]\n", curr_db_ver, version)

	// walk the nodes from back to front
	var found_current bool
	for _, node := range self.revisions {
		if !found_current {
			if node.version == curr_db_ver {
				found_current = true
			} else {
				continue
			}
		}

		fmt.Printf("Processing downgrade from [%v] to [%v]\n", node.version, node.prev)

		// Process this node
		curr_patch_dir, err = GetPatchDirectory(patch_root, node.version)
		if node.version == curr_db_ver {
			downgrade_sql := filepath.Join(curr_patch_dir, "downgrade.sql")

			if file_exists(downgrade_sql) {
				fmt.Printf("Reading from :[%v]\n", downgrade_sql)
				downgrade_bytes, err = ioutil.ReadFile(downgrade_sql)

				sql_cmd = string(downgrade_bytes)
				fmt.Printf("Attempting SQL is: [%v]\n", sql_cmd)
				txn, err = self.Db.Begin()
				if _, err = txn.Exec(sql_cmd); err != nil {
					fmt.Printf("Failed to execute: [%s]\n", sql_cmd)
					txn.Rollback()
					return err
				}
			} else {
				return fmt.Errorf("No downgrade is possible from [%v] to [%v]\n", node.version, node.prev)
			}

			// Roll the version back
			_, err = txn.Exec("update meta set value = $1 where key = 'db.hash';", node.prev)
			if err != nil {
				txn.Rollback()
				return err
			}
			fmt.Printf("Version switched from : [%v]\n", curr_db_ver)
			curr_db_ver = node.prev
			fmt.Printf("Version switched to   : [%v]\n", node.prev)
			txn.Commit()
			fmt.Printf("Success!  Executed [%v]\n", sql_cmd)
		}

		if curr_db_ver == version {
			fmt.Printf("Downgrade to [%v] completed!", version)
			// We're done
			break
		}
	}
	return err
}

func (self *DBRcs) Changelog(patch_root string) (err error) {
	var desc_bytes []byte

	if err = self.ComputeHistory(patch_root); err != nil {
		return err
	}

	fmt.Printf("Most recent version is at the top:\n==========================\n")
	for _, node := range self.revisions {
		patch_dir, err := GetPatchDirectory(patch_root, node.version)

		desc_filename := filepath.Join(patch_dir, "description.txt")
		if desc_bytes, err = ioutil.ReadFile(desc_filename); err != nil {
			return err
		}

		if node.prev != "" {
			fmt.Printf("[%v] -> [%v] : %v\n", node.prev, node.version, string(desc_bytes))
		} else {
			fmt.Printf("[%v] : %v\n", node.version, string(desc_bytes))
		}
	}
	return nil
}

func (self *DBRcs) FindLastVersion(patch_root string) (result string, err error) {
	/*
		Find all schema patches and find the latest version.

		If no versions exist yet, then return "" as the latest version
		and nil as the error.

		If multiple heads exist, return an error.
	*/
	prev_set := make(map[string]bool)
	curr_set := make(map[string]bool)

	matches, err := filepath.Glob(filepath.Join(patch_root, "*"))
	if err != nil {
		return "", nil
	}
	for _, rev_dir := range matches {
		prev_filename := path.Join(rev_dir, "prev.txt")
		if !file_exists(prev_filename) {
			// skip this directory
			continue
		}

		_, dirname := path.Split(rev_dir)
		curr_rev := strings.Split(dirname, ".")[0]

		prev_rev, err := get_prev_rev(prev_filename)
		if err != nil {
			return "", nil
		} else if prev_rev != "" {
			prev_set[prev_rev] = true
		}

		curr_set[curr_rev] = true
	}

	if len(curr_set) == 0 && len(prev_set) == 0 {
		// This is the first version
		return "", nil
	}

	// Compare the two sets and find the head
	found_head := false
	head_rev := ""
	for rev := range curr_set {
		if _, ok := prev_set[rev]; !ok {
			if !found_head {
				found_head = true
				head_rev = rev
			} else if found_head {
				// There are multiple heads
				return "", fmt.Errorf("Found multiple heads: [%v] and [%v]", head_rev, rev)
			}
		}
	}

	if head_rev != "" {
		return head_rev, nil
	}
	return "", fmt.Errorf("Can't find HEAD revision")
}

func get_prev_rev(prev_filename string) (prev_rev string, err error) {
	/*
		Read
	*/
	var bytes []byte
	bytes, err = ioutil.ReadFile(prev_filename)
	if err != nil {
		return "", err
	}
	return string(bytes), err
}

func (self *DBRcs) ComputeHistory(patch_root string) (err error) {
	/*
		Compute the revision history by walking backwards in the
		history. This should rewrite the revisions slice with the most
		recent version at index 0 and the oldest version at the end
		of the list.
	*/

	// Reset the slice to empty
	self.revisions = self.revisions[:0]

	var curr_rev, prev_rev string
	curr_rev, err = self.FindLastVersion(patch_root)

	if err != nil {
		return err
	}
	for {
		curr_patch_dir, err := GetPatchDirectory(patch_root, curr_rev)
		if err != nil {
			return err
		}
		prev_filename := filepath.Join(curr_patch_dir, "prev.txt")
		prev_rev, err = get_prev_rev(prev_filename)
		if err != nil {
			return err
		}

		// inject this revision at the head of the
		// revisions list
		node := new(versionNode)
		node.version = curr_rev
		node.prev = prev_rev
		self.revisions = append(self.revisions, node)

		if prev_rev == "" {
			// This is the initial commit
			break
		}

		curr_rev = prev_rev
	}
	return err
}

func prepend(slice []*versionNode, elem *versionNode) []*versionNode {
	slice = append(slice, elem)
	copy(slice[1:], slice[0:])
	slice[0] = elem
	return slice
}

func file_exists(filename string) bool {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return false
	}
	return true
}

func clean_description(desc string) (result string) {
	/*
		Clean up the description for a filename

		 1. turn everything lowercase
		 2. remove all charcters outside of [0-9a-z]
		 3. replace all white space with _
		 4. replace _+ characters with a single underscore
	*/

	x := strings.ToLower(desc)
	re := regexp.MustCompile("[^a-z0-9]")
	y := string(re.ReplaceAll([]byte(x), []byte("_")))
	re = regexp.MustCompile("_+")
	y = string(re.ReplaceAll([]byte(y), []byte("_")))
	y = y[:minInt(40, len(y))]
	return y
}

// TODO: pull this together with wmf/utils:minInt
// There's no built in min function.
// awesome.
func minInt(x, y int) int {
	if x < y {
		return x
	}
	return y
}

func GetPatchDirectory(patch_root, revision string) (result string, err error) {
	var glob_matches []string
	glob_matches, err = filepath.Glob(filepath.Join(patch_root, revision+"*"))
	if err != nil {
		return "", err
	}
	return glob_matches[0], err
}

func (self *DBRcs) CreateNextRev(patch_root string, description string) (prev string, rev string, err error) {
	/*
			Generates a new version directory with template files in it.
			Returns the previous version, current version and an error.
			In the case this is the first revision, prev is set to the empty string.

		 1. A sha1 is generated based on the previous revision code (if
		    it exists), and the cleaned up description
	*/
	var patch_dir string
	var intPerm int64

	prev, err = self.FindLastVersion(patch_root)
	if err != nil {
		return "", "", err
	}

	// compute a new revision
	h := sha1.New()
	if prev != "" {
		io.WriteString(h, prev)
	}
	io.WriteString(h, clean_description(description))
	rev = fmt.Sprintf("%x", h.Sum(nil))

	// Use at least 12 characters, possibly more for uniqueness
	prefix_len := 12
	for {
		matches, err := filepath.Glob(filepath.Join(patch_root, rev[:prefix_len]+"*"))
		if err != nil {
			return "", "", err
		}
		if len(matches) == 0 {
			rev = rev[:prefix_len]
			break
		}
		prefix_len += 1
	}

	// create the directory
	short_patch_dir := fmt.Sprintf("%s.%s", rev, time.Now().UTC().Format("20060102"))
	patch_dir = filepath.Join(patch_root, short_patch_dir)

	intPerm, _ = strconv.ParseInt("700", 8, 32)

	err = os.MkdirAll(patch_dir, os.FileMode(intPerm))
	if err != nil {
		return "", "", err
	}

	err = simplewrite(filepath.Join(patch_dir, "description.txt"), description)
	if err != nil {
		return "", "", err
	}

	// write prev revision
	err = simplewrite(filepath.Join(patch_dir, "prev.txt"), prev)
	if err != nil {
		return "", "", err
	}

	// write upgrade.sql
	err = simplewrite(filepath.Join(patch_dir, "upgrade.sql"),
		"-- create table foo (first_col integer, second_col integer);\n")
	if err != nil {
		return "", "", err
	}

	err = simplewrite(filepath.Join(patch_dir, "downgrade.sql.orig"),
		"-- drop table foo;\n")
	if err != nil {
		return "", "", err
	}

	return prev, rev, nil
}
