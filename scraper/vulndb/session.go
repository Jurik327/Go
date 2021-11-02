package vulndb

import (
	"time"

	"xorm.io/xorm"
)

// VulnDBSession is a session wrapper for orm with automatic commit for every `insertCount` insertions.
// Keeps track of insertion count and speed.
type VulnDBSession struct {
	orm        *xorm.Engine
	curSession *xorm.Session

	insertCount int64

	startTime        time.Time
	totalInsertCount int64

	insertCommitThreshold int64

	printstats           bool
	insertStatsThreshold int64

	// Cached CVE results.
	cached map[string][]CVEMatch

	// Product and vendor cache by id.
	productCache map[int64]*vulndbProduct
	vendorCache  map[int64]*VulndbVendor
}

// NewSessionWrapper returns an initializes VulnDBSession for `orm`.
func NewSessionWrapper(orm *xorm.Engine) *VulnDBSession {
	sw := &VulnDBSession{}
	sw.orm = orm

	sw.insertCount = 0

	utcNow := time.Now().UTC()
	sw.startTime = utcNow
	sw.totalInsertCount = 0

	sw.insertCommitThreshold = 50000

	sw.printstats = true
	sw.insertStatsThreshold = 100000

	sw.cached = map[string][]CVEMatch{}
	sw.productCache = map[int64]*vulndbProduct{}
	sw.vendorCache = map[int64]*VulndbVendor{}

	return sw
}

// GetProductById returns product by id with a caching mechanism.
func (sw *VulnDBSession) GetProductById(productId int64) (*vulndbProduct, error) {
	product, has := sw.productCache[productId]
	if !has {
		var p vulndbProduct
		has, err := sw.Where(`id = ?`, productId).Get(&p)
		if err != nil {
			log.Debugf("ERROR: %v", err)
			return nil, err
		}
		if !has {
			log.Debugf("ERROR: Product ID missing - skipping")
			return nil, nil
		}
		sw.productCache[productId] = &p
		product = &p
	}

	return product, nil
}

// GetVendorById returns vendor by id with a caching mechanism.
func (sw *VulnDBSession) GetVendorById(vendorId int64) (*VulndbVendor, error) {
	vendor, has := sw.vendorCache[vendorId]
	if !has {
		var v VulndbVendor
		has, err := sw.Where(`id = ?`, vendorId).Get(&v)
		if err != nil {
			log.Debugf("ERROR: %v", err)
			return nil, err
		}
		if !has {
			log.Debugf("ERROR: Vendor ID missing - skipping")
			return nil, nil
		}
		sw.vendorCache[vendorId] = &v
		vendor = &v
	}

	return vendor, nil
}

func (sw *VulnDBSession) Raw() (*xorm.Session, error) {
	return sw.session()
}

func (sw *VulnDBSession) CommitAndRestart() error {
	if sw.curSession != nil {
		err := sw.curSession.Commit()
		if err != nil {
			return err
		}
		sw.curSession.Close()
		sw.curSession = nil
	}

	session := sw.orm.NewSession()
	err := session.Begin()
	if err != nil {
		return err
	}

	sw.curSession = session
	return nil
}

// session returns current session, recycling every 5000 counts.
func (sw *VulnDBSession) session() (*xorm.Session, error) {
	if sw.curSession == nil || sw.insertCount == sw.insertCommitThreshold {
		sw.insertCount = 0
		err := sw.CommitAndRestart()
		if err != nil {
			return nil, err
		}
	}

	return sw.curSession, nil
}

func (sw *VulnDBSession) Exec(sqlStr string, args ...interface{}) error {
	session, err := sw.session()
	if err != nil {
		return err
	}

	params := append([]interface{}{sqlStr}, args...)
	_, err = session.Exec(params...) //sqlStr, args...)
	return err
}

func (sw *VulnDBSession) Insert(beans ...interface{}) error {
	session, err := sw.session()
	if err != nil {
		return err
	}
	_, err = session.Insert(beans...)
	if err != nil {
		return err
	}

	sw.insertCount++
	sw.totalInsertCount++

	// In benchmarking mode:
	if sw.printstats {
		sw.printSpeed()
	}
	return nil
}

func (sw *VulnDBSession) Sql(queryStr string, args ...interface{}) *VulnDBSession {
	session, _ := sw.session()
	sw.curSession = session.SQL(queryStr, args...)
	return sw
}

func (sw *VulnDBSession) Where(queryStr string, args ...interface{}) *VulnDBSession {
	session, _ := sw.session()
	sw.curSession = session.Where(queryStr, args...)
	return sw
}

func (sw *VulnDBSession) OrderBy(order string) *VulnDBSession {
	session, _ := sw.session()
	sw.curSession = session.OrderBy(order)
	return sw
}

func (sw *VulnDBSession) Get(bean interface{}) (bool, error) {
	session, err := sw.session()
	if err != nil {
		return false, err
	}
	return session.Get(bean)
}

func (sw *VulnDBSession) Find(rowsSlicePtr interface{}, condiBean ...interface{}) error {
	session, err := sw.session()
	if err != nil {
		return err
	}
	return session.Find(rowsSlicePtr, condiBean...)
}

func (sw *VulnDBSession) Commit() error {
	if sw.curSession != nil {
		err := sw.curSession.Commit()
		if err != nil {
			return err
		}
	}
	return nil
}

func (sw *VulnDBSession) Close() error {
	if sw != nil && sw.curSession != nil {
		sw.curSession.Close()
		sw.curSession = nil
	}
	return nil
}

func (sw *VulnDBSession) CommitAndClose() error {
	err := sw.Commit()
	if err != nil {
		return err
	}

	if sw.curSession != nil {
		sw.curSession.Close()
		sw.curSession = nil
	}
	return nil
}

func (sw *VulnDBSession) printSpeed() {
	if sw.totalInsertCount%sw.insertStatsThreshold == 0 {

		utcNow := time.Now().UTC()
		secs := utcNow.Sub(sw.startTime).Seconds()
		speed := float64(sw.totalInsertCount) / secs

		log.Debugf("%d Insertions in %.0f seconds", sw.totalInsertCount, secs)
		log.Debugf("[Insertion speed: %.1f inserts/sec]", speed)
	}
}
