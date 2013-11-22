package storage

import (
    "mozilla.org/util"
    _ "github.com/lib/pq"
    "database/sql"

    "fmt"
    //"log"
    //"sync/atomic"
    "time"
)

type Storage struct {
    config util.JsMap
    logger *util.HekaLogger
    dsn string
    dbh *sql.DB
}

type Position struct {
    Latitude float32
    Longitude float32
    Altitude float32
    Time int64
}

type Device struct {
    ID string                       // device Id
    LastPosition Position           // last reported position
    PreviousPosition [5]Position
    Lockable bool                   // is device lockable
    Secret string                   // HAWK secret
    PushUrl string                  // SimplePush URL
    Pending string                  // pending command
}


type Users map[string]string

/* Relative:

    table userToDeviceMap:
        userId   UUID index
        deviceId UUID

    table deviceInfo:
        deviceId       UUID index
        lockable       boolean
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

    // TODO: create a cache of handles?
    logger.Info("storage", dsn, nil)
    if dbh, err := sql.Open("postgres",dsn); err == nil {
        store = &Storage{config: config,
                         logger:logger,
                         dsn: dsn,
                         dbh: dbh}
        if err = store.Init(); err != nil {
            return nil, err
        }
        return store, nil
    } else {
        logger.Critical("storage", "Could not open database",
            util.Fields{"error":err.Error()})
        return nil, err
    }
}

func (self *Storage) Init() (err error){
    cmds := []string{
    "create table if not exists userToDeviceMap (userId uuid, deviceId uuid);",
    "create index on userToDeviceMap (userId);",

    "create table if not exists deviceInfo ( deviceId uuid, lockable boolean, lastExchange timestamp, hawkSecret varchar(100), pendingCommand varchar(100));",
    "create index on deviceInfo (deviceId);",

    "create table if not exists position ( id bigserial, deviceId uuid, expry interval, time  timestamp, latitude real, longitude real, altitude real);",
    "create index on position (deviceId);",
    }

    dbh := self.dbh
    defer dbh.Close()
    db, err := dbh.Begin()
    if err != nil {
        self.logger.Error("storage", "Could not open db",
            util.Fields{"error": err.Error()})
        return err
    }

    for _,s := range cmds {
        _, err := db.Exec(s)
        if err != nil {
            self.logger.Error("storage", "Could not initialize db",
                util.Fields{"cmd": s, "error": err.Error()})
            return err
        }
    }

    return nil
}

func (self *Storage) CreateDevice(dev Device) (devId string, err error) {
    // value check?

    sql := "insert into deviceInfo (deviceId, lockable, lastExchange, hawkSecret) select $1, $2, $3, $4 where not exists (select deviceId from deviceInfo where deviceId = $1);"
    if dev.ID == "" {
        dev.ID, _ = util.GenUUID4()
    }
    dbh := self.dbh
    defer dbh.Close()
    db, err := dbh.Begin()
    if err != nil {
        self.logger.Error("storage", "Could not insert device",
                util.Fields{"error": err.Error()})
        return "", err
    }

    if _, err := db.Exec(sql, dev.ID,
        dev.Lockable,
        time.Now().String(),
        dev.Secret,
       dev.PushUrl); err != nil {
            self.logger.Error("storage", "Could not create device",
                util.Fields{"error":err.Error()})
            return "", err
    }
    return dev.ID, nil
}


