package storage

import (
	"database/sql"
	// _ "github.com/jbarham/gopgsqldriver"
	_ "github.com/lib/pq"
	"mozilla.org/util"

	"errors"
	"fmt"
	"strconv"
	"time"
)

var DatabaseError = errors.New("Database Error")

type Storage struct {
	config   util.JsMap
	logger   *util.HekaLogger
	dsn      string
	logCat   string
	defExpry int64
}

type Position struct {
	Latitude  float32
	Longitude float32
	Altitude  float32
	Time      int32
}

type Device struct {
	ID                string // device Id
	Name              string
	PreviousPositions []Position
	Lockable          bool   // is device lockable
	LoggedIn          bool   // is the device logged in
	Secret            string // HAWK secret
	PushUrl           string // SimplePush URL
	Pending           string // pending command
	LastExchange      int32  // last time we did anything
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

   table deviceInfo:
       deviceId       UUID index
       name           string
       lockable       boolean
       loggedin       boolean
       lastExchange   time
       hawkSecret     string
       pushUrl        string
       pendingCommand string

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

	store = &Storage{config: config,
		logger:   logger,
		logCat:   logCat,
		defExpry: defExpry,
		dsn:      dsn}
	if err = store.Init(); err != nil {
		return nil, err
	}
	return store, nil
}

func (self *Storage) Init() (err error) {
	cmds := []string{
		"create table if not exists userToDeviceMap (userId varchar, deviceId varchar, name varchar);",
		"create index on userToDeviceMap (userId);",

		"create table if not exists deviceInfo ( deviceId varchar, lockable boolean, loggedin boolean, lastExchange timestamp, hawkSecret varchar, pushurl varchar, pendingCommand varchar);",
		"create index on deviceInfo (deviceId);",

		"create table if not exists position ( id bigserial, deviceId varchar, expry interval, time  timestamp, latitude real, longitude real, altitude real);",
		"create index on position (deviceId);",
		"create or replace function update_time() returns trigger as $$ begin new.lastexchange = now(); return new; end; $$ language 'plpgsql';",
		"drop trigger if exists update_le on deviceinfo;",
		"create trigger update_le before update on deviceinfo for each row execute procedure update_time();",
	}

	dbh, err := self.openDb()
	if err != nil {
		return err
	}
	defer dbh.Close()

	for _, s := range cmds {
		res, err := dbh.Exec(s)
        self.logger.Debug(self.logCat, "db init",
            util.Fields{"cmd":s, "res": fmt.Sprintf("%+v", res)})
		if err != nil {
			self.logger.Error(self.logCat, "Could not initialize db",
				util.Fields{"cmd": s, "error": err.Error()})
			return err
		}
	}

	return nil
}

func (self *Storage) RegisterDevice(userid string, dev Device) (devId string, err error) {
	// value check?

	statement := "insert into deviceInfo (deviceId, lockable, loggedin, lastExchange, hawkSecret) select $1, $2, $3, $4, $5 where not exists (select deviceId from deviceInfo where deviceId = $1);"
	if dev.ID == "" {
		dev.ID, _ = util.GenUUID4()
	}
	dbh, err := self.openDb()
	defer dbh.Close()
	if err != nil {
		self.logger.Error(self.logCat, "Could not insert device",
			util.Fields{"error": err.Error()})
		return "", err
	}

	if _, err = dbh.Exec(statement, dev.ID,
		dev.Lockable,
		time.Now().String(),
		dev.Secret,
		dev.PushUrl); err != nil {
		self.logger.Error(self.logCat, "Could not create device",
			util.Fields{"error": err.Error()})
		return "", err
	}
	if _, err = dbh.Exec("insert into userToDeviceMap (userId, deviceId) values ($1, $2);", userid, dev.ID); err != nil {
		self.logger.Error(self.logCat, "Could not map device to user", util.Fields{
			"uid":      userid,
			"deviceId": devId,
			"error":    err.Error()})
		return "", err
	}
	return dev.ID, nil
}

func (self *Storage) GetDeviceInfo(userId string, devId string) (devInfo *Device, err error) {

	// collect the data for a given device for display

	var deviceId, pushUrl, name []uint8
	var lockable, loggedIn bool
	var statement string
	var positions []Position

	dbh, err := self.openDb()
	if err != nil {
		self.logger.Error(self.logCat, "Could not open DB",
			util.Fields{"error": err.Error()})
		return nil, err
	}
	defer dbh.Close()

	// verify that the device belongs to the user
	statement = "select d.deviceId, u.name, d.lockable, d.loggedin, d.pushUrl from userToDeviceMap as u, deviceInfo as d where u.userId = $1 and u.deviceId=$2 and u.deviceId=d.deviceId;"
	stmt, err := dbh.Prepare(statement)
	if err != nil {
		self.logger.Error(self.logCat, "Could not query device info",
			util.Fields{"error": err.Error()})
		return nil, err
	}
	row, err := stmt.Query(userId, devId)
	if err != nil {
		self.logger.Error(self.logCat, "Could not query device info",
			util.Fields{"error": err.Error()})
		return nil, err
	}
	row.Next()
	err = row.Scan(&deviceId, &name, &lockable, &loggedIn, &pushUrl)
	switch {
	case err == sql.ErrNoRows:
		return nil, nil
	case err != nil:
		self.logger.Error(self.logCat, "Could not fetch device info",
			util.Fields{"error": err.Error(),
				"userId":   userId,
				"deviceId": devId})
		return nil, err
	default:
	}
	statement = "select extract(epoch from time)::int, latitude, longitude, altitude from position where deviceid=$1 order by time desc limit 10;"
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
				Latitude:  latitude,
				Longitude: longitude,
				Altitude:  altitude,
				Time:      time})
		}
		// gather the positions
	} else {
		self.logger.Error(self.logCat, "Could not get positions",
			util.Fields{"error": err.Error()})
	}

	reply := &Device{ID: string(deviceId),
		Name:              string(name),
		Lockable:          lockable,
		LoggedIn:          loggedIn,
		PreviousPositions: positions,
		PushUrl:           string(pushUrl)}

	/*
		self.logger.Debug(self.logCat, "Device info",
	    util.Fields{"userId":userId,
	        "device": deviceId,
	        "data": fmt.Sprintf("%v\n", reply)})
	*/
	return reply, nil
}

func (self *Storage) GetPending(devId string) (cmd Unstructured, err error) {
	// TODO: Get pending commands
	return nil, nil
}

func (self *Storage) GetDevicesForUser(userId string) (devices []DeviceList, err error) {
	//TODO: get list of devices
	var data []DeviceList

	dbh, err := self.openDb()
	defer dbh.Close()

	statement := "select deviceId, name, from userToDeviceMap where userId = $1;"
	rows, err := dbh.Query(statement, userId)
	for rows.Next() {
		var id, name string
		err = rows.Scan(&id, &name)
		if err != nil {
			self.logger.Error(self.logCat, "Could not get list of devices for user",
				util.Fields{"error": err.Error(),
					"user": userId})
			return nil, err
		}
		data = append(data, DeviceList{ID: id, Name: name})
	}
	return data, nil
}

func (self *Storage) openDb() (dbh *sql.DB, err error) {
	if dbh, err = sql.Open("postgres", self.dsn); err != nil {
		return nil, err
	}
	err = dbh.Ping()
	if err != nil {
		self.logger.Error(self.logCat, "Could not ping open db", util.Fields{"error": err.Error()})
		return nil, err
	}
	return dbh, nil
}

func (self *Storage) StoreCommand(devId, command string) (err error) {
    //update device table to store command where devId = $1
    sql := "update deviceInfo set pendingCommand = $2 where devId=$1;"
    dbh, err := self.openDb()
    defer dbh.Close()
    if err != nil {
        self.logger.Error(self.logCat, "Could not open db",
            util.Fields{"error": err.Error()})
        return err
    }

    if _, err = dbh.Exec(sql, devId, command); err != nil {
        self.logger.Error(self.logCat, "Could not store pending command",
            util.Fields{"error": err.Error()})
        return err
    }
    return nil
}

func (self *Storage) ValidateDevice(devId string) (valid bool) {
	var err error
	if devId == "" {
		return false
	}
	// TODO: validate that we've seen this ID
	statement := "select deviceId from deviceInfo where deviceId = $1;"

	dbh, err := self.openDb()
	defer dbh.Close()
	if err == nil {
		return false
	}

	row := dbh.QueryRow(statement, devId)
	var slice []string
	err = row.Scan(&slice)
	if err != nil {
		self.logger.Error(self.logCat, "Error finding device",
			util.Fields{"error": err.Error(),
				"device": devId})
		return false
	}
	self.logger.Info(self.logCat, "verify device",
		util.Fields{"device": devId,
			"result": fmt.Sprintf("%v", slice)})
	if len(slice) == 0 {
		return false
	}

	return true
}

func (self *Storage) SetDeviceLocked(devId string, state bool) (err error) {
	// TODO: update the device record
	dbh, err := self.openDb()
	defer dbh.Close()
	if err != nil {
		return err
	}

	statement := "update deviceInfo set lockable = $1 where deviceId =$2"

	_, err = dbh.Exec(statement)
	if err != nil {
		self.logger.Error(self.logCat, "Could not set device lock state",
			util.Fields{"error": err.Error(),
				"device": devId,
				"state":  fmt.Sprintf("%b", state)})
		return err
	}
	return nil
}

func (self *Storage) SetDeviceLocation(devId string, position Position) (err error) {
	// TODO: set the current device position
	dbh, err := self.openDb()
	defer dbh.Close()
	if err != nil {
		return err
	}
	posId, _ := util.GenUUID4()
	now := time.Now().UTC()

	statement := "insert into position (positionId, deviceId, time, latitude, longitude, altitude) values ($1, $2, $3, $4, $5, $6);"
	_, err = dbh.Exec(statement, posId, devId, now,
		position.Latitude,
		position.Longitude,
		position.Altitude)
	if err != nil {
		self.logger.Error(self.logCat, "Error inserting postion",
			util.Fields{"error": err.Error()})
		return err
	}
	statement = "delete position where positionId in ( select positionId from ( select positionId, row_number() over (order by time desc) RowNumber from position where time > $1 ) tt where RowNumber > 1"
	_, err = dbh.Exec(statement, time.Now().Unix()+self.defExpry)
	if err != nil {
		self.logger.Error(self.logCat, "Error gc'ing positions",
			util.Fields{"error": err.Error()})
		return err
	}
	return nil
}

func (self *Storage) LogState(devId string, cmd string) (err error) {
	return nil
}
