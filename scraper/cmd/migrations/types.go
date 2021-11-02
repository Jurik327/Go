package migrations

import (
	"strconv"

	"github.com/op/go-logging"
)

const (
	MIGRATION_DATE_FORMAT = "20060102150405"
)

type MigrationId uint64

type MigrationMap map[MigrationId]Migration

func migIdArrayLess(a, b MigrationId) bool { return a < b }

func MigrationIdFromString(str string) (MigrationId, error) {
	ret, err := strconv.ParseUint(str, 10, 0)
	return MigrationId(ret), err
}

var log = logging.MustGetLogger("migrations")
