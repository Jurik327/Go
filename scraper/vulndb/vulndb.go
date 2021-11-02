package vulndb

import (
	"os"
	"time"

	logging "github.com/op/go-logging"
	"xorm.io/xorm"
)

var log = logging.MustGetLogger("vulndb")

// VulnDB represents the Nanitor vulnerability database, which is stored as a flat file SQLite3 database.
type VulnDB struct {
	dbPath   string
	lastmod  time.Time
	lastsize int64
	orm      *xorm.Engine
}

// New loads the VulnDB from an SQlite3 file specified by `dbPath`. Still returns an object on error, one such case is
// when the file does not exist. It then gets lazily created later.
func New(dbPath string) (*VulnDB, error) {
	vdb := &VulnDB{}
	vdb.dbPath = dbPath

	finfo, err := os.Stat(dbPath)
	if err != nil {
		return vdb, err
	}

	orm, err := xorm.NewEngine("sqlite3", dbPath)
	if err != nil {
		return vdb, err
	}

	vdb.lastsize = finfo.Size()
	vdb.lastmod = finfo.ModTime()
	vdb.orm = orm
	return vdb, nil
}

// NewSession returns a new VulnDBSession. Handles automatic refreshing of the DB if
// vulndb file has changed.
func (vdb *VulnDB) NewSession() (*VulnDBSession, error) {
	err := vdb.refresh()
	if err != nil {
		return nil, err
	}
	return NewSessionWrapper(vdb.orm), nil
}

// Refresh refreshes the ORM if needed.
func (vdb *VulnDB) refresh() error {
	finfo, err := os.Stat(vdb.dbPath)
	if err != nil {
		return err
	}

	// Reload if changed.
	if finfo.Size() != vdb.lastsize || finfo.ModTime().After(vdb.lastmod) {
		if vdb.orm != nil {
			// We haven't managed to create a VDB yet, perhaps the vulndb file has not been created yet.
			err = vdb.orm.Close()
			if err != nil {
				return err
			}
		}

		vdb2, err := New(vdb.dbPath)
		if err != nil {
			return err
		}
		// Update.
		vdb.orm = vdb2.orm
		vdb.lastsize = vdb2.lastsize
		vdb.lastmod = vdb2.lastmod
		log.Debugf("Reloaded VulnDB ORM")
	}

	return nil
}

// Close closes the database and commits the transaction.
func (vdb *VulnDB) Close() error {
	if vdb.orm == nil {
		return nil
	}
	return vdb.orm.Close()
}
