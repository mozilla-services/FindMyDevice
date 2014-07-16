/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package storage

import (
	"github.com/mozilla-services/FindMyDevice/util"

	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

var ErrDatabase = errors.New("Database Error")
var ErrUnknownDevice = errors.New("Unknown device")

const (
	DB_VERSION = "20140707"
)

// Storage abstration
type Storage struct {
	config   *util.MzConfig
	logger   *util.HekaLogger
	metrics  *util.Metrics
	dsn      string
	logCat   string
	defExpry int64
	maxDev   int64
	db       *sql.DB
}

// Device position
type Position struct {
	Latitude  float64
	Longitude float64
	Altitude  float64
	Accuracy  float64
	Time      int64
	Cmd       map[string]interface{}
}

// Device information
type Device struct {
	ID                string // device Id
	User              string // userID
	Name              string
	PreviousPositions []Position
	HasPasscode       bool   // is device lockable
	LoggedIn          bool   // is the device logged in
	Secret            string // HAWK secret
	PushUrl           string // SimplePush URL
	Pending           string // pending command
	LastExchange      int32  // last time we did anything
	Accepts           string // commands the device accepts
	AccessToken       string // OAuth Access token
}

type DeviceList struct {
	ID   string
	Name string
}

// Generic structure useful for JSON
type Unstructured map[string]interface{}

/* Relative:

   table userToDeviceMap:
       userId   UUID index
       deviceId UUID

   table pendingCommands:
       deviceId UUID index
       time     timeStamp
       cmd      string

   table deviceInfo:
       deviceId       UUID index
       name           string
       lockable       boolean
       lastExchange   time
       hawkSecret     string
       pushUrl        string
       accepts        string
       accesstoken    string

   table position:
       positionId UUID index
       deviceId   UUID index
       time       timeStamp
       latitude   float
       longitude  float
       altitude   float
       accuracy   float

   // misc administrivia table.
   table meta:
       key        string
       value      string
*/
/* key:
deviceId {positions:[{lat:float, lon: float, alt: float, time:int},...],
		 lockable: bool
		 lastExchange: int
		 secret: string
		 pending: string
		}

user [deviceId:name,...]
*/

// Get a time string that makes psql happy.
func dbNow() (ret string) {
	r, _ := time.Now().UTC().MarshalText()
	return string(r)
}

// Open the database.
func Open(config *util.MzConfig, logger *util.HekaLogger, metrics *util.Metrics) (store *Storage, err error) {
	dsn := fmt.Sprintf("user=%s password=%s host=%s dbname=%s sslmode=%s",
		config.Get("db.user", "user"),
		config.Get("db.password", "password"),
		config.Get("db.host", "localhost"),
		config.Get("db.db", "wmf"),
		config.Get("db.sslmode", "disable"))
	logCat := "storage"
	// default expry is 5 days
	defExpry, err := strconv.ParseInt(config.Get("db.default_expry", "432000"), 0, 64)
	if err != nil {
		defExpry = 432000
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		panic("Storage is unavailable: " + err.Error() + "\n")
	}
	db.SetMaxIdleConns(100)
	if err = db.Ping(); err != nil {
		return nil, err
	}
	maxDev, err := strconv.ParseInt(config.Get("db.max_devices_per_user", "1"), 0, 64)
	if err != nil {
		maxDev = 1
	}

	store = &Storage{
		config:   config,
		logger:   logger,
		logCat:   logCat,
		defExpry: defExpry,
		maxDev:   maxDev,
		metrics:  metrics,
		dsn:      dsn,
		db:       db}
	return store, nil
}

// Create the tables, indexes and other needed items.
func (self *Storage) Init() (err error) {
	var statement string
	var tmp string

	dbh := self.db
	err = dbh.QueryRow("select value from meta where key = 'db.ver';").Scan(&tmp)
	if err == nil && tmp == DB_VERSION {
		self.logger.Info(self.logCat, "Database up to date",
			util.Fields{"version": DB_VERSION})
		return err
	}
	if err != sql.ErrNoRows {
		panic(fmt.Sprintf("err: %+v\n", err))
	}
	statement = "select table_name from information_schema.tables where table_name='meta' and table_schema='public';"
	err = dbh.QueryRow(statement).Scan(&tmp)
	if err == sql.ErrNoRows {
		//initialize the table
		self.createDb()
	}
	// check for updates
	self.markDb(DB_VERSION)
	return nil
}

func (self *Storage) createDb() (err error) {
	// TODO: create a versioned db update system that contains commands
	// to execute.
	// read the create_db.sql file and build the database

	panic("Please run the commands in sql/create_db.sql")
	/*
		        // note: indexes may return an error if they already exist.
				for _, s := range cmds {
					res, err := dbh.Exec(s)
					self.logger.Debug(self.logCat, "db init",
						util.Fields{"cmd": s, "res": fmt.Sprintf("%+v", res)})
					if err != nil {
						self.logger.Error(self.logCat, "Could not initialize db",
							util.Fields{"cmd": s, "error": err.Error()})
						return err
					}
				}
			}
	*/
	//TODO get lastDbUpdate from meta, if there's a file in sql older
	// than that, run it. (allows for db patching.)
	// self.dbUpdated()
}

func (self *Storage) markDb(date string) (err error) {
	fmt.Printf("### marking db\n")
	dbh := self.db
	result, err := dbh.Exec("update meta set val=$2 where key=$1;",
		"db.ver", date)
	if err != nil {
		return err
	}
	if cnt, err := result.RowsAffected(); cnt == 0 || err != nil {
		_, err = dbh.Exec("insert into meta (key, val) values ($1, $2);",
			"db.ver", date)
		return err
	}
	return nil
}

// Register a new device to a given userID.
func (self *Storage) RegisterDevice(userid string, dev Device) (devId string, err error) {
	var deviceId string
	dbh := self.db

	if dev.ID == "" {
		dev.ID, _ = util.GenUUID4()
	}
	// if the device belongs to the user already...
	err = dbh.QueryRow("select deviceid from userToDeviceMap where userId = $1 and deviceid=$2;", userid, dev.ID).Scan(&deviceId)
	if err == nil && deviceId == dev.ID {
		self.logger.Debug(self.logCat, "Updating db",
			util.Fields{"userId": userid, "deviceid": dev.ID})
		rows, err := dbh.Query("update deviceinfo set lockable=$1, loggedin=$2, lastExchange=$3, hawkSecret=$4, accepts=$5, pushUrl=$6 where deviceid=$7;",
			dev.HasPasscode,
			dev.LoggedIn,
			dbNow(),
			dev.Secret,
			dev.Accepts,
			dev.PushUrl,
			dev.ID)
		defer rows.Close()
		if err != nil {
			self.logger.Warn(self.logCat, "Device Info Update error",
				util.Fields{"error": err.Error()})
			return "", err
		} else {
			return dev.ID, nil
		}
	}
	// otherwise insert it.
	statement := "insert into deviceInfo (deviceId, lockable, loggedin, lastExchange, hawkSecret, accepts, pushUrl) values ($1, $2, $3, $4, $5, $6, $7);"
	rows, err := dbh.Query(statement,
		string(dev.ID),
		dev.HasPasscode,
		dev.LoggedIn,
		dbNow(),
		dev.Secret,
		dev.Accepts,
		dev.PushUrl)
	defer rows.Close()
	if err != nil {
		self.logger.Error(self.logCat, "Could not create device",
			util.Fields{"error": err.Error(),
				"device": fmt.Sprintf("%+v", dev)})
		return "", err
	}
	rows2, err := dbh.Query("insert into userToDeviceMap (userId, deviceId, name, date) values ($1, $2, $3, now());", userid, dev.ID, dev.Name)
	defer rows2.Close()
	if err != nil {
		switch {
		default:
			self.logger.Error(self.logCat,
				"Could not map device to user",
				util.Fields{
					"uid":      userid,
					"deviceId": dev.ID,
					"name":     dev.Name,
					"error":    err.Error()})
			return "", err
		}
	}
	return dev.ID, nil
}

// Return known info about a device.
func (self *Storage) GetDeviceInfo(devId string) (devInfo *Device, err error) {

	// collect the data for a given device for display

	var deviceId, userId, pushUrl, name, secret, lestr, accesstoken []uint8
	var lastexchange float64
	var hasPasscode, loggedIn bool
	var statement, accepts string

	dbh := self.db

	// verify that the device belongs to the user
	statement = "select d.deviceId, u.userId, coalesce(u.name,d.deviceId), d.lockable, d.loggedin, d.pushUrl, d.accepts, d.hawksecret, extract(epoch from d.lastexchange), d.accesstoken from userToDeviceMap as u, deviceInfo as d where u.deviceId=$1 and u.deviceId=d.deviceId;"
	stmt, err := dbh.Prepare(statement)
	if err != nil {
		self.logger.Error(self.logCat, "Could not query device info",
			util.Fields{"error": err.Error()})
		return nil, err
	}
	defer stmt.Close()
	err = stmt.QueryRow(devId).Scan(&deviceId, &userId, &name, &hasPasscode,
		&loggedIn, &pushUrl, &accepts, &secret, &lestr, &accesstoken)
	switch {
	case err == sql.ErrNoRows:
		return nil, ErrUnknownDevice
	case err != nil:
		self.logger.Error(self.logCat, "Could not fetch device info",
			util.Fields{"error": err.Error(),
				"deviceId": devId})
		return nil, err
	default:
	}
	lastexchange, _ = strconv.ParseFloat(string(lestr), 32)
	//If we have a pushUrl, the user is logged in.
	bloggedIn := string(pushUrl) != ""
	reply := &Device{
		ID:           string(deviceId),
		User:         string(userId),
		Name:         string(name),
		Secret:       string(secret),
		HasPasscode:  hasPasscode,
		LoggedIn:     bloggedIn,
		LastExchange: int32(lastexchange),
		PushUrl:      string(pushUrl),
		Accepts:      accepts,
		AccessToken:  string(accesstoken),
	}

	return reply, nil
}

func (self *Storage) GetPositions(devId string) (positions []Position, err error) {

	dbh := self.db

	statement := "select extract(epoch from time)::int, latitude, longitude, altitude, accuracy from position where deviceid=$1 order by time limit 1;"
	rows, err := dbh.Query(statement, devId)
	defer rows.Close()
	if err == nil {
		var time int32
		var latitude float32
		var longitude float32
		var altitude float32
		var accuracy float32

		for rows.Next() {
			err = rows.Scan(&time, &latitude, &longitude, &altitude, &accuracy)
			if err != nil {
				self.logger.Error(self.logCat, "Could not get positions",
					util.Fields{"error": err.Error(),
						"deviceId": devId})
				break
			}
			positions = append(positions, Position{
				Latitude:  float64(latitude),
				Longitude: float64(longitude),
				Altitude:  float64(altitude),
				Accuracy:  float64(accuracy),
				Time:      int64(time)})
		}
		// gather the positions
	} else {
		self.logger.Error(self.logCat, "Could not get positions",
			util.Fields{"error": err.Error()})
	}

	return positions, nil

}

// Get pending commands.
func (self *Storage) GetPending(devId string) (cmd, ctype string, err error) {
	dbh := self.db
	var created = time.Time{}

	statement := "select id, cmd, type, time from pendingCommands where deviceId = $1 order by time limit 1;"
	rows, err := dbh.Query(statement, devId)
	defer rows.Close()
	if rows.Next() {
		var id string
		err = rows.Scan(&id, &cmd, &ctype, &created)
		if err != nil {
			self.logger.Error(self.logCat, "Could not read pending command",
				util.Fields{"error": err.Error(),
					"deviceId": devId})
			return "", "", err
		}
		// Convert the date string to an int64
		lifespan := int64(time.Now().UTC().Sub(created).Seconds())
		self.metrics.Timer("cmd.pending", lifespan)
		statement = "delete from pendingCommands where id = $1"
		dbh.Exec(statement, id)
	}
	self.Touch(devId)
	return cmd, ctype, nil
}

func (self *Storage) GetUserFromDevice(deviceId string) (userId, name string, err error) {

	dbh := self.db
	statement := "select userId, name from userToDeviceMap where deviceId = $1 limit 1;"
	rows, err := dbh.Query(statement, deviceId)
	defer rows.Close()
	if err == nil {
		for rows.Next() {
			err = rows.Scan(&userId, &name)
			if err != nil {
				self.logger.Error(self.logCat,
					"Could not get user for device",
					util.Fields{"error": err.Error(),
						"user": deviceId})
				return "", "", err
			}
			return userId, name, nil
		}
	}
	return "", "", ErrUnknownDevice
}

// Get all known devices for this user.
func (self *Storage) GetDevicesForUser(userId, oldUserId string) (devices []DeviceList, err error) {
	var data []DeviceList

	dbh := self.db
	limit := self.config.Get("db.max_devices_for_user", "1")
	// Update from the old sha hash to the new FxA UID if need be.
	if len(oldUserId) > 0 && userId != oldUserId {
		upd := "update userToDeviceMap set userId = $1 where userId = $2;"
		updr, err := dbh.Exec(upd, userId, oldUserId)
		if err != nil {
			self.logger.Error(self.logCat,
				"Could not update UserID",
				util.Fields{"userID": userId,
					"oldUserId": oldUserId,
					"error":     err.Error()})
			// Crap, that didn't work. get the old userids
			userId = oldUserId
		} else {
			hits, err := updr.RowsAffected()
			if err == nil {
				self.metrics.IncrementBy("db.UserID.Updated", int(hits))
			}
		}
	}
	statement := "select deviceId, coalesce(name,deviceId) from userToDeviceMap where userId = $1 order by date desc limit $2;"
	rows, err := dbh.Query(statement, userId, limit)
	defer rows.Close()
	if err == nil {
		for rows.Next() {
			var id, name string
			err = rows.Scan(&id, &name)
			if err != nil {
				self.logger.Error(self.logCat,
					"Could not get list of devices for user",
					util.Fields{"error": err.Error(),
						"user": userId})
				return nil, err
			}
			data = append(data, DeviceList{ID: id, Name: name})
		}
	}
	return data, err
}

// Store a command into the list of pending commands for a device.
func (self *Storage) StoreCommand(devId, command, cType string) (err error) {
	//update device table to store command where devId = $1
	dbh := self.db

	result, err := dbh.Exec("update pendingCommands set time=$1, cmd=$2 where deviceid=$3 and type=$4;",
		dbNow(),
		command,
		devId,
		cType)
	if err != nil {
		self.logger.Error(self.logCat,
			"Could not update command",
			util.Fields{"error": err.Error()})
		return err
	}
	if cnt, err := result.RowsAffected(); cnt == 0 || err != nil {
		self.logger.Debug(self.logCat,
			"Storing Command",
			util.Fields{"deviceId": devId,
				"command": command})
		if _, err = dbh.Exec("insert into pendingCommands (deviceid, time, cmd, type) values( $1, $2, $3, $4);",
			devId,
			dbNow(),
			command,
			cType); err != nil {
			self.logger.Error(self.logCat,
				"Could not store pending command",
				util.Fields{"error": fmt.Sprintf("%+v", err)})
			return err
		}
	}
	return nil
}

func (self *Storage) SetAccessToken(devId, token string) (err error) {
	dbh := self.db

	statement := "update deviceInfo set accesstoken = $1, lastexchange = now() where deviceId = $2"
	_, err = dbh.Exec(statement, token, devId)
	if err != nil {
		self.logger.Error(self.logCat, "Could not set the access token",
			util.Fields{"error": err.Error(),
				"device": devId,
				"token":  token})
		return err
	}
	return nil
}

// Shorthand function to set the lock state for a device.
func (self *Storage) SetDeviceLock(devId string, state bool) (err error) {
	dbh := self.db

	statement := "update deviceInfo set lockable = $1, lastexchange = now()  where deviceId =$2"
	_, err = dbh.Exec(statement, state, devId)
	if err != nil {
		self.logger.Error(self.logCat, "Could not set device lock state",
			util.Fields{"error": err.Error(),
				"device": devId,
				"state":  fmt.Sprintf("%b", state)})
		return err
	}
	return nil
}

// Add the location information to the known set for a device.
func (self *Storage) SetDeviceLocation(devId string, position Position) (err error) {
	dbh := self.db

	// Only keep the latest positon (changed requirements from original design)
	self.PurgePosition(devId)

	statement := "insert into position (deviceId, time, latitude, longitude, altitude, accuracy) values ($1, $2, $3, $4, $5, $6);"
	st, err := dbh.Prepare(statement)
	_, err = st.Exec(
		devId,
		dbNow(),
		float32(position.Latitude),
		float32(position.Longitude),
		float32(position.Altitude),
		float32(position.Accuracy))
	st.Close()
	if err != nil {
		self.logger.Error(self.logCat, "Error inserting postion",
			util.Fields{"error": err.Error()})
		return err
	}
	return nil
}

// Remove old postion information for devices.
// This previously removed "expired" location records. We currently only
// retain the latest record for a user.
func (self *Storage) GcDatabase(devId, userId string) (err error) {
	dbh := self.db

	// because prepare doesn't like single quoted vars
	// because calling dbh.Exec() causes a lock race condition.
	// because I didn't have enough reasons to drink.
	// Delete old records (except the latest one) so we always have
	// at least one position record.
	// Added bonus: The following string causes the var replacer to
	// get confused and toss an error, so yes, currently this uses inline
	// replacement.
	//	statement := fmt.Sprintf("delete from position where id in (select id from (select id, row_number() over (order by time desc) RowNumber from position where time < (now() - interval '%d seconds') ) tt where RowNumber > 1);", self.defExpry)
	statement := fmt.Sprintf("delete from position where time < (now() - interval '%d seconds');", self.defExpry)
	st, err := dbh.Prepare(statement)
	_, err = st.Exec()
	st.Close()
	if err != nil {
		self.logger.Error(self.logCat, "Error gc'ing positions",
			util.Fields{"error": err.Error()})
		return err
	}
	// TODO: convert the following into statements
	/*
	   // remove "extra" devices registered to the user
	   // check this sql
	   delete from usertodevicemap where id in (select id from
	       (select id, row_number() over (order by date desc) RowNumber from
	       usertodevicemap) tt where RowNumber > 1);

	   // delete devices with no "owner".
	   delete from deviceinfo where deviceinfo.deviceid in
	       (select deviceinfo.deviceid from deviceinfo left join
	        usertodevicemap on usertodevicemap.deviceid =
	        deviceinfo.deviceid where usertodevicemap.deviceid is null);
	*/

	return nil
}

// remove all tracking information for devId.
func (self *Storage) PurgePosition(devId string) (err error) {
	dbh := self.db

	statement := "delete from position where deviceid = $1;"
	if _, err = dbh.Exec(statement, devId); err != nil {
		return err
	}
	return nil
}

func (self *Storage) Touch(devId string) (err error) {
	dbh := self.db

	statement := "update deviceInfo set lastexchange = now() where deviceid = $1"
	_, err = dbh.Exec(statement, devId)
	if err != nil {
		return err
	}

	return nil
}

func (self *Storage) DeleteDevice(devId string) (err error) {
	dbh := self.db

	var tables = []string{"pendingcommands",
		"position",
		"usertodevicemap",
		"deviceinfo"}

	for t := range tables {
		// BURN THE WITCH!
		table := tables[t]
		_, err = dbh.Exec("delete from "+table+" where deviceid=$1;", devId)
		if err != nil {
			self.logger.Error(self.logCat,
				"Could not nuke data from table",
				util.Fields{"error": err.Error(),
					"device": devId,
					"table":  table})
			return err
		}
	}
	return nil
}

func (self *Storage) getMeta(key string) (val string, err error) {
	var row *sql.Row
	dbh := self.db

	statement := "select value from meta where key=$1;"
	if row = dbh.QueryRow(statement, key); row != nil {
		row.Scan(&val)
		return val, err
	}
	return "", err
}

func (self *Storage) setMeta(key, val string) (err error) {
	var statement string
	dbh := self.db

	// try to update or insert.
	statement = "update meta set value = $2 where key = $1;"
	if res, err := dbh.Exec(statement, key, val); err != nil {
		return err
	} else {
		if cnt, _ := res.RowsAffected(); cnt == 0 {
			statement = "insert into met (key, value) values ($1, $2);"
			if _, err = dbh.Exec(statement, key, val); err != nil {
				return err
			}
		}
	}
	return nil
}

func (self *Storage) Close() {
	self.db.Close()
}

/* Nonce handler.
   Anything that can be killed, can be overkilled.
*/

func (self *Storage) genSig(key, val string) string {
	// Yes, this is using woefully insecure MD5. That's ok.
	// Collisions should be rare enough and this is more
	// paranoid security than is really required.
	sig := md5.New()
	io.WriteString(sig, key+"."+val)
	return hex.EncodeToString(sig.Sum(nil))
}

// Generate a nonce for OAuth checks
func (self *Storage) GetNonce() (string, error) {
	var statement string
	dbh := self.db

	key, _ := util.GenUUID4()
	val, _ := util.GenUUID4()
	statement = "insert into nonce (key, val, time) values ($1, $2, current_timestamp);"

	if _, err := dbh.Exec(statement, key, val); err != nil {
		return "", err
	}
	ret := key + "." + self.genSig(key, val)
	return ret, nil
}

// Does the user's nonce match?
func (self *Storage) CheckNonce(nonce string) (bool, error) {
	var statement string
	dbh := self.db

	// gc nonces before checking.
	statement = "delete from nonce where time < current_timestamp - interval '5 minutes';"
	dbh.Exec(statement)

	keysig := strings.SplitN(nonce, ".", 2)
	if len(keysig) != 2 {
		self.logger.Warn(self.logCat,
			"Invalid nonce",
			util.Fields{"nonce": nonce})
		return false, nil
	}
	statement = "select val from nonce where key = $1 limit 1;"
	rows, err := dbh.Query(statement, keysig[0])
	defer rows.Close()
	if err == nil {
		for rows.Next() {
			var val string
			err = rows.Scan(&val)
			if err == nil {
				dbh.Exec("delete from nonce where key = $1;", keysig[0])
				sig := self.genSig(keysig[0], val)
				return sig == keysig[1], nil
			}
			self.logger.Error(self.logCat,
				"Nonce check error",
				util.Fields{"error": err.Error()})
			return false, err
		}
		// Not found
		return false, nil
	}
	// An error happened.
	self.logger.Error(self.logCat,
		"Nonce check error",
		util.Fields{"error": err.Error()})
	return false, err
}
