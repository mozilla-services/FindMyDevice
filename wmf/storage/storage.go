/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package storage

import (
	"github.com/mozilla-services/FindMyDevice/util"

	"errors"

	_ "github.com/lib/pq"
)

var ErrDatabase = errors.New("Database Error")
var ErrUnknownDevice = errors.New("Unknown device")

const (
	DB_VERSION = "20140707"
)

type Storage interface {
	Init() error
	RegisterDevice(string, *Device) (string, error)
	GetDeviceInfo(string) (*Device, error)
	GetPositions(string) ([]Position, error)
	GetPending(string) (string, string, error)
	GetUserFromDevice(string) (string, string, error)
	GetDevicesForUser(string, string) ([]DeviceList, error)
	StoreCommand(string, string, string) error
	SetAccessToken(string, string) error
	SetDeviceLock(string, bool) error
	SetDeviceLocation(string, *Position) error
	GcDatabase(string, string) error
	PurgePosition(string) error
	Touch(string) error
	DeleteDevice(string) error
	PurgeCommands(string) error
	Close()
	GetNonce() (string, error)
	CheckNonce(string) (bool, error)
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

type AvailableStorage map[string]func(*util.MzConfig, util.Logger, util.Metrics) (Storage, error)

var AvailableStores = make(AvailableStorage)
