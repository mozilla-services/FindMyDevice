/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package storage

import (
	"database/sql"
	_ "github.com/lib/pq"
	"mozilla.org/util"

	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

var DatabaseError = errors.New("Database Error")

type Storage struct {
	config   util.JsMap
	logger   *util.HekaLogger
	dsn      string
	logCat   string
	defExpry int64
	db       *sql.DB
}

type Position struct {
	Latitude  float64
	Longitude float64
	Altitude  float64
	Time      int64
    Lockable  bool
}

type Device struct {
	ID                string // device Id
	User              string // userID
	Name              string
	PreviousPositions []Position
	Lockable          bool   // is device lockable
	LoggedIn          bool   // is the device logged in
	Secret            string // HAWK secret
	PushUrl           string // SimplePush URL
	Pending           string // pending command
	LastExchange      int32  // last time we did anything
	Accepts           string // commands the device accepts
}

type DeviceList struct {
	ID   string
	Name string
}

type Unstructured map[string]interface{}

type Users map[string]string

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
       loggedin       boolean
       lastExchange   time
       hawkSecret     string
       pushUrl        string
       pendingCommand string
       accepts        string

   table position:
       positionId UUID index
       deviceId   UUID index
       expry      interval index
       time       timeStamp
       latitude   float
       longitude  float
       altitude   float
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
// Using Relative for now, because backups.

var ErrUnknownDevice = errors.New("Unknown device")

// Get a time string that makes psql happy.
func dbNow() (ret string) {
	r, _ := time.Now().UTC().MarshalText()
	return string(r)
}

// Open the database.
func Open(config util.JsMap, logger *util.HekaLogger) (store *Storage, err error) {
	dsn := fmt.Sprintf("user=%s password=%s host=%s dbname=%s sslmode=%s",
		util.MzGet(config, "db.user", "user"),
		util.MzGet(config, "db.password", "password"),
		util.MzGet(config, "db.host", "localhost"),
		util.MzGet(config, "db.db", "wmf"),
		util.MzGet(config, "db.sslmode", "disable"))
	logCat := "storage"
	defExpry, err := strconv.ParseInt(util.MzGet(config, "db.default_expry", "1500"), 0, 64)
	if err != nil {
		defExpry = 1500
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxIdleConns(100)
	if err = db.Ping(); err != nil {
		return nil, err
	}
	store = &Storage{
		config:   config,
		logger:   logger,
		logCat:   logCat,
		defExpry: defExpry,
		dsn:      dsn,
		db:       db}
	if err = store.Init(); err != nil {
		return nil, err
	}
	return store, nil
}

// Create the tables, indexes and other needed items.
func (self *Storage) Init() (err error) {
	// TODO: create a versioned db update system that contains commands
	// to execute.
	cmds := []string{
		"create table if not exists userToDeviceMap (userId varchar, deviceId varchar, name varchar);",
		"create index on userToDeviceMap (userId);",
		"create unique index on userToDeviceMap (userId, deviceId);",

		"create table if not exists deviceInfo (deviceId varchar unique, lockable boolean, loggedin boolean, lastExchange timestamp, hawkSecret varchar, pushurl varchar, accepts varchar);",
		"create index on deviceInfo (deviceId);",

		"create table if not exists pendingCommands (id bigserial, deviceId varchar, time timestamp, cmd varchar);",
		"create index on pendingCommands (deviceId);",

		"create table if not exists position (id bigserial, deviceId varchar, expry interval, time  timestamp, latitude real, longitude real, altitude real);",
		"create index on position (deviceId);",
		"create or replace function update_time() returns trigger as $$ begin new.lastexchange = now(); return new; end; $$ language 'plpgsql';",
		"drop trigger if exists update_le on deviceinfo;",
		"create trigger update_le before update on deviceinfo for each row execute procedure update_time();",
        "set time zone utc;",
	}

	dbh := self.db
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

	return nil
}

// Register a new device to a given userID.
func (self *Storage) RegisterDevice(userid string, dev Device) (devId string, err error) {
	// value check?
	statement := "insert into deviceInfo (deviceId, lockable, loggedin, lastExchange, hawkSecret, accepts, pushUrl) values ($1, $2, $3, $4, $5, $6, $7);"
	if dev.ID == "" {
		dev.ID, _ = util.GenUUID4()
	}
	dbh := self.db
	if err != nil {
		self.logger.Error(self.logCat, "Could not insert device",
			util.Fields{"error": err.Error()})
		return "", err
	}
	if _, err = dbh.Exec(statement,
		string(dev.ID),
		dev.Lockable,
		dev.LoggedIn,
		dbNow(),
		dev.Secret,
		dev.Accepts,
		dev.PushUrl); err != nil {
		if strings.Contains(err.Error(), "duplicate key value") {
			fmt.Printf("#### Updating... \n")
			statement = "update deviceinfo set lockable=$2, accepts=$3, pushUrl=$4, hawkSecret=$5 where deviceId=$1"
			if _, err = dbh.Exec(statement,
				string(dev.ID),
				dev.Lockable,
				dev.Accepts,
				dev.PushUrl,
                dev.Secret,
			); err != nil {
				self.logger.Error(self.logCat, "Could not update device",
					util.Fields{"error": err.Error(),
						"device": fmt.Sprintf("%+v", dev)})
				return "", err
			}
			statement = "update usertodevicemap set name = $1 where deviceId=$2 and userId=$3"
			if _, err = dbh.Exec(statement,
				string(dev.Name),
				string(dev.ID),
				userid,
			); err != nil {
				self.logger.Error(self.logCat,
					"Could not update device name",
					util.Fields{"error": err.Error(),
						"device": fmt.Sprintf("%+v", dev),
						"userid": userid})
				return "", err
			}
		} else {
			self.logger.Error(self.logCat, "Could not create device",
				util.Fields{"error": err.Error(),
					"device": fmt.Sprintf("%+v", dev)})
			return "", err
		}
	} else {
		if _, err = dbh.Exec("insert into userToDeviceMap (userId, deviceId, name) values ($1, $2, $3);", userid, dev.ID, dev.Name); err != nil {
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
	}
	return dev.ID, nil
}

// Return known info about a device.
func (self *Storage) GetDeviceInfo(devId string) (devInfo *Device, err error) {

	// collect the data for a given device for display

	var deviceId, userId, pushUrl, name, secret, lestr []uint8
	var lastexchange float64
	var lockable, loggedIn bool
	var statement, accepts string

	dbh := self.db

	// verify that the device belongs to the user
	statement = "select d.deviceId, u.userId, coalesce(u.name,d.deviceId), d.lockable, d.loggedin, d.pushUrl, d.accepts, d.hawksecret, extract(epoch from d.lastexchange) from userToDeviceMap as u, deviceInfo as d where u.deviceId=$1 and u.deviceId=d.deviceId;"
	stmt, err := dbh.Prepare(statement)
	if err != nil {
		self.logger.Error(self.logCat, "Could not query device info",
			util.Fields{"error": err.Error()})
		return nil, err
	}
	defer stmt.Close()
	row := stmt.QueryRow(devId)
	err = row.Scan(&deviceId, &userId, &name, &lockable,
		&loggedIn, &pushUrl, &accepts, &secret, &lestr)
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
		Lockable:     lockable,
		LoggedIn:     bloggedIn,
		LastExchange: int32(lastexchange),
		PushUrl:      string(pushUrl),
		Accepts:      accepts,
	}

	return reply, nil
}

// Oh, db driver, why do you make me hate you so?
func (self *Storage) GetPositions(devId string) (positions []Position, err error) {

	dbh := self.db

	statement := "select extract(epoch from time)::int, latitude, longitude, altitude from position where deviceid=$1 order by time limit 10;"
	rows, err := dbh.Query(statement, devId)
	if err == nil {
		var time int32 = 0
		var latitude float32 = 0.0
		var longitude float32 = 0.0
		var altitude float32 = 0.0

		for rows.Next() {
			err = rows.Scan(&time, &latitude, &longitude, &altitude)
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
				Time:      int64(time)})
		}
		// gather the positions
		rows.Close()
	} else {
		self.logger.Error(self.logCat, "Could not get positions",
			util.Fields{"error": err.Error()})
	}

	return positions, nil

}

// Get pending commands.
func (self *Storage) GetPending(devId string) (cmd string, err error) {
	dbh := self.db

	statement := "select id, cmd from pendingCommands where deviceId = $1 order by time limit 1;"
	rows, err := dbh.Query(statement, devId)
	if rows.Next() {
		var id string
		err = rows.Scan(&id, &cmd)
		if err != nil {
			self.logger.Error(self.logCat, "Could not read pending command",
				util.Fields{"error": err.Error(),
					"deviceId": devId})
			return "", err
		}
		statement = "delete from pendingCommands where id = $1"
		dbh.Exec(statement, id)
	}
    self.Touch(devId)
	return cmd, nil
}

// Get all known devices for this user.
func (self *Storage) GetDevicesForUser(userId string) (devices []DeviceList, err error) {
	//TODO: get list of devices
	var data []DeviceList

	dbh := self.db
	if err != nil {
		return nil, err
	}

	statement := "select deviceId, coalesce(name,deviceId) from userToDeviceMap where userId = $1;"
	rows, err := dbh.Query(statement, userId)
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
func (self *Storage) StoreCommand(devId, command string) (err error) {
	//update device table to store command where devId = $1
	statement := "insert into pendingCommands (deviceId, time, cmd) values ($1, $2,  $3);"
	dbh := self.db

	if err != nil {
		self.logger.Error(self.logCat, "Could not open db",
			util.Fields{"error": err.Error()})
		return err
	}
	self.logger.Info(self.logCat, "Storing Command",
		util.Fields{"deviceId": devId, "command": command})

	if _, err = dbh.Exec(statement, devId, dbNow(), command); err != nil {
		self.logger.Error(self.logCat, "Could not store pending command",
			util.Fields{"error": err.Error()})
		return err
	}
	return nil
}

// Shorthand function to set the lock state for a device.
func (self *Storage) SetDeviceLockable(devId string, state bool) (err error) {
	// TODO: update the device record
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
	// TODO: set the current device position
	dbh := self.db

	statement := "insert into position (deviceId, time, latitude, longitude, altitude) values ($1, $2, $3, $4, $5);"
	st, err := dbh.Prepare(statement)
	_, err = st.Exec(
		devId,
		dbNow(),
		float32(position.Latitude),
		float32(position.Longitude),
		float32(position.Altitude))
	st.Close()
	if err != nil {
		self.logger.Error(self.logCat, "Error inserting postion",
			util.Fields{"error": err.Error()})
		return err
	}
	return nil
}

// Remove old postion information for devices.
func (self *Storage) GcPosition(devId string) (err error) {
	dbh := self.db

	// because prepare doesn't like single quoted vars
	// because calling dbh.Exec() causes a lock race condition.
	// because I didn't have enough reasons to drink.
	// Delete old records (except the latest one) so we always have
	// at least one position record.
	statement := fmt.Sprintf("delete from position where id in (select id from (select id, row_number() over (order by time desc) RowNumber from position where time < (now() - interval '%d seconds') ) tt where RowNumber > 1);",
		self.defExpry)
	st, err := dbh.Prepare(statement)
	_, err = st.Exec()
	st.Close()
	if err != nil {
		self.logger.Error(self.logCat, "Error gc'ing positions",
			util.Fields{"error": err.Error()})
		return err
	}
	return nil
}

func (self *Storage) Touch(devId string) (err error) {
	dbh := self.db

	sql := "update deviceInfo set lastexchange = now() where deviceid = $1"
	_, err = dbh.Exec(sql, devId)
	if err != nil {
		return err
	}

	return nil
}

func (self *Storage) DeleteDevice(devId string) (err error) {
    dbh := self.db

    var tables = []string{"pendingcommands", "position", "usertodevice",
        "deviceinfo"}

    for t := range tables {
        // BURN THE WITCH!
        table := tables[t]
        _, err = dbh.Exec("delete from $1 where deviceid=$2;", table, devId)
        if err != nil {
            self.logger.Error(self.logCat,
                "Could not nuke data from table",
                util.Fields{"error": err.Error(),
                    "device": devId,
                    "table": table})
            return err
        }
    }
    return nil
}
