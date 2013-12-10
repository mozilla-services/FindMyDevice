package storage

import (
    "mozilla.org/util"
    _ "github.com/lib/pq"
    "database/sql"

    "errors"
    "fmt"
    //"log"
    //"sync/atomic"
    "strconv"
    "time"
)


var DatabaseError = errors.New("Database Error");

type Storage struct {
    config util.JsMap
    logger *util.HekaLogger
    dsn string
    logCat string
    defExpry int64
}

type Position struct {
    Latitude float64
    Longitude float64
    Altitude float64
    Time int64
}

type Device struct {
    ID string                       // device Id
    Name string
    PreviousPosition [5]Position
    Lockable bool                   // is device lockable
    Secret string                   // HAWK secret
    PushUrl string                  // SimplePush URL
    Pending string                  // pending command
}

type DeviceList struct {
    ID string
    Name string
}

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
    dsn := fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=%s",
        util.MzGet(config, "db.user", "user"),
        util.MzGet(config, "db.password", "password"),
        util.MzGet(config, "db.host", "localhost"),
        util.MzGet(config, "db.db", "wmf"),
        util.MzGet(config, "db.sslmode", "disable"))
    logCat := "storage"
    defExpry, err := strconv.ParseInt(util.MzGet(config, "db.default_expry", "1500"),0, 64)
    if err != nil {
        defExpry = 1500
    }

    store = &Storage{config: config,
                         logger:logger,
                         logCat: logCat,
                         defExpry: defExpry,
                         dsn: dsn}
   if err = store.Init(); err != nil {
            return nil, err
   }
   return store, nil
}

func (self *Storage) Init() (err error){
    cmds := []string{
    "create table if not exists userToDeviceMap (userId varchar, deviceId varchar, name varchar);",
    "create index on userToDeviceMap (userId);",

    "create table if not exists deviceInfo ( deviceId uuid, lockable boolean, loggedin boolean, lastExchange timestamp, hawkSecret varchar(100), pendingCommand varchar(100));",
    "create index on deviceInfo (deviceId);",

    "create table if not exists position ( id bigserial, deviceId uuid, expry interval, time  timestamp, latitude real, longitude real, altitude real);",
    "create index on position (deviceId);",
    }

    dbh, db, err := self.openDb()
    if err != nil {
        return err
    }
    defer dbh.Close()

    for _,s := range cmds {
        _, err := db.Exec(s)
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
    dbh, db, err := self.openDb()
    defer dbh.Close()
    if err != nil {
        self.logger.Error(self.logCat, "Could not insert device",
                util.Fields{"error": err.Error()})
        return "", err
    }

    if _, err = db.Exec(statement, dev.ID,
        dev.Lockable,
        time.Now().String(),
        dev.Secret,
       dev.PushUrl); err != nil {
            self.logger.Error(self.logCat, "Could not create device",
                util.Fields{"error":err.Error()})
            return "", err
    }
    if _, err = db.Exec("insert into userToDeviceMap (userId, deviceId) values ($1, $2);", userid, dev.ID); err != nil {
        self.logger.Error(self.logCat, "Could not map device to user", util.Fields{
            "uid": userid,
            "deviceId": devId,
            "error": err.Error()})
        return "", err
    }
    return dev.ID, nil
}

func (self *Storage) GetDeviceInfo(userId string, devId string) (devInfo map[string]interface{}, err error) {

    // collect the data for a given device for display

    var deviceId, pushUrl, name []uint8
    var lockable, loggedIn bool
    var  statement string

    dbh, db, err := self.openDb()
    defer dbh.Close()

    // verify that the device belongs to the user
    statement = "select d.deviceId, u.name, d.lockable, d.loggedin, d.pushUrl from userToDeviceMap as u, deviceInfo as d where u.userId = $1 and u.deviceId=$2 and u.deviceId=d.deviceId;"
    fmt.Printf("userId:%s, devId:%s\n", userId, devId)
    row := db.QueryRow(statement, userId, devId)
    err = row.Scan(&deviceId, &name, &lockable, &loggedIn, &pushUrl)
    switch {
    case err == sql.ErrNoRows:
        return nil, nil
    case err != nil:
        self.logger.Error(self.logCat, "Could not fetch device info",
            util.Fields{"error": err.Error(),
                        "userId": userId,
                        "deviceId":  devId})
        return nil, err
    }
    reply := map[string]interface{}{"deviceid":string(deviceId),
                                   "name": string(name),
                                   "lockable":lockable,
                                   "loggedin":loggedIn,
                                   "pushurl":string(pushUrl)}

                                   statement = "select extract(epoch from time)::int, latitude, longitude, altitude from position where deviceid=$1 order by time desc limit 10;"
    rows, err := db.Query(statement, devId)
    if err == nil {
        var time int32 = 0
        var latitude float32 = 0.0
        var longitude float32 = 0.0
        var altitude float32 = 0.0
        var positions []map[string]interface{}

        for rows.Next() {
            err = rows.Scan(&time, &latitude, &longitude, &altitude)
            if err != nil {
                self.logger.Error(self.logCat, "Could not get positions",
                    util.Fields{"error": err.Error(),
                                "deviceId": devId})
                break;
            }
            positions = append(positions, map[string]interface{}{
                "latitude":latitude,
                "longitude":longitude,
                "altitude": altitude,
                "time":time})
        }
        // gather the positions
        reply["positions"] = positions
    } else {
        self.logger.Error(self.logCat, "Could not get positions",
        util.Fields{"error": err.Error()})
    }

    fmt.Printf("%v\n", reply)
    return reply, nil
}


func (self *Storage) GetPending(devId string) (cmd map[string]interface{}, err error){
    // TODO: Get pending commands
    return nil, nil
}

func (self *Storage) GetDevicesForUser(userId string) (devices []string, err error) {
    //TODO: get list of devices
    var data DeviceList

    statement = "select deviceId, name, from userToDeviceMap where userId = $1;"
    rows := db.Query(statement, userId)
    for rows.Next() {
        var id, name string
        err = rows.Scan(&id, &name)
        if err != nil {
            self.logger.Error(self.logCat, "Could not get list of devices for user",
                util.Fields{"error", err.Error(),
                            "user", userId})
            return nil, err
        }
        data = append(data, DeviceList{ID: id, Name: name})
    }
    return data, nil
}

func (self *Storage) openDb() (dbh *sql.DB, db *sql.Tx, err error) {
    if dbh, err = sql.Open("postgres", self.dsn); err != nil {
        return nil, nil, err
    }
    db, err = dbh.Begin()
    if err != nil {
        self.logger.Error(self.logCat, "Could not open db", util.Fields{"error": err.Error()})
        return nil, nil, err
    }
    return dbh, db, nil
}


func (self *Storage) ValidateDevice(devId string) (valid bool) {
    var err error
    if devId == "" {
        return false
    }
    // TODO: validate that we've seen this ID
    statement := "select deviceId from deviceInfo where deviceId = $1;"

    dbh, db, err := self.openDb()
    defer dbh.Close()
    if err == nil {
        return false
    }

    row := db.QueryRow(statement, devId)
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
    dbh, db, err := self.openDb()
    defer dbh.Close()
    if err != nil {
        return err
    }

    statement := "update deviceInfo set lockable = $1 where deviceId =$2"

    _,err = db.Exec(statement)
    if err != nil {
        self.logger.Error(self.logCat, "Could not set device lock state",
            util.Fields{"error": err.Error(),
                    "device": devId,
                    "state": fmt.Sprintf("%b", state)})
            return err
    }
    return nil
}

func (self *Storage) SetDeviceLocation(devId string, position Position) (err error) {
    // TODO: set the current device position
    dbh, db, err := self.openDb()
    defer dbh.Close()
    if err != nil {
        return err
    }
    posId,_ := util.GenUUID4()
    now := time.Now().UTC()

    statement := "insert into position (positionId, deviceId, time, latitude, longitude, altitude) values ($1, $2, $3, $4, $5, $6);"
    _, err = db.Exec(statement, posId, devId, now,
        position.Latitude,
        position.Longitude,
        position.Altitude);
    if err != nil {
        self.logger.Error(self.logCat, "Error inserting postion",
            util.Fields{"error": err.Error()})
        return err
    }
    statement = "delete position where positionId in ( select positionId from ( select positionId, row_number() over (order by time desc) RowNumber from position where time > $1 ) tt where RowNumber > 1"
    _, err = db.Exec(statement, time.Now().Unix() + self.defExpry)
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
