package migrations

import (
	_ "database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/ty/fun"
	"xorm.io/xorm"
)

type MigrationManager struct {
	Directory string
	Session   *xorm.Session
}

func (m MigrationManager) makeIdentifier() (MigrationId, error) {
	now := time.Now().UTC()
	dateString := now.Format(MIGRATION_DATE_FORMAT)
	return MigrationIdFromString(dateString)
}

// Name should be DATE_Message_up|down.sql
func (m MigrationManager) CreateNew(message string) {
	identifier, _ := m.makeIdentifier()
	prefix := fmt.Sprintf("%d", identifier)
	if message != "" {
		message = strings.Replace(message, " ", "_", -1)
		prefix += fmt.Sprintf("_%s", message)
	}

	upName := fmt.Sprintf("%s_up.sql", prefix)
	downName := fmt.Sprintf("%s_down.sql", prefix)

	migUp := filepath.Join(m.Directory, upName)
	migDown := filepath.Join(m.Directory, downName)

	out, _ := os.Create(migUp)
	defer out.Close()

	out, _ = os.Create(migDown)
	defer out.Close()
}

// E.g. 20140405213503_Initial_Migration_down.sql
func (m MigrationManager) CollectMigrations() ([]MigrationId, MigrationMap, error) {
	items := MigrationMap{}
	var previousMigration MigrationId

	availMigrations := []MigrationId{}

	err := filepath.Walk(m.Directory, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if fi.IsDir() {
			return nil
		}

		migName := fi.Name()

		migIdIdx := strings.Index(migName, "_")
		if migIdIdx == -1 {
			return nil
		}

		lastIdx := strings.LastIndexAny(migName, "_")
		if lastIdx < migIdIdx {
			return nil
		}

		migrationId, err := MigrationIdFromString(migName[0:migIdIdx])
		if err != nil {
			return nil
		}

		prefix := migName[0:lastIdx]

		if _, ok := items[migrationId]; ok {
			return nil
		}

		currentMigration := Migration{
			MigrationId: migrationId,
			Prefix:      prefix,
			PreviousId:  previousMigration,
		}

		availMigrations = append(availMigrations, migrationId)
		items[migrationId] = currentMigration
		previousMigration = currentMigration.MigrationId

		return nil
	})

	// Sort the available migrations.
	availMigrations = fun.QuickSort(migIdArrayLess, availMigrations).([]MigrationId)
	return availMigrations, items, err
}

func (m MigrationManager) CheckTable() error {
	_, err := m.Session.Exec("CREATE TABLE IF NOT EXISTS schema_migrations( id SERIAL NOT NULL, version bigint UNIQUE NOT NULL )")
	return err
}

func (m MigrationManager) ClearTable() error {
	_, err := m.Session.Exec("DELETE FROM schema_migrations")
	return err
}

func (m MigrationManager) GetLatestMigration() (MigrationId, error) {
	var schemaMigration SchemaMigration
	has, err := m.Session.Get(&schemaMigration)
	if !has {
		return 0, nil
	}

	return MigrationId(schemaMigration.Version), err
}

func (m MigrationManager) SetVersion(version MigrationId) error {
	var schemaMigration SchemaMigration
	has, err := m.Session.Get(&schemaMigration)
	if err != nil {
		return err
	}

	isNew := false

	if !has {
		schemaMigration = SchemaMigration{}
		isNew = true
	}

	schemaMigration.Version = int64(version)

	if isNew {
		_, err = m.Session.Insert(schemaMigration)
	} else {
		_, err = m.Session.ID(schemaMigration.Id).Cols("version").Update(&schemaMigration)
	}

	return err
}
