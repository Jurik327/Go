package migrations

import (
	"fmt"
	"io/ioutil"
)

func MigrateUpgrade(manager *MigrationManager, requested string, pretend bool) error {
	err := manager.CheckTable()
	if err != nil {
		return err
	}

	availMigrations, migrationMap, err := manager.CollectMigrations()
	if err != nil {
		return err
	}

	// Need to check at what migration the database is.
	latestMigration, err := manager.GetLatestMigration()
	if err != nil {
		return err
	}

	var requestedId MigrationId

	// If explicitly wanting a non-head we need to check that it is a valid version.
	if requested != "head" {
		requestedId, err = MigrationIdFromString(requested)
		if err != nil {
			return fmt.Errorf("Invalid version given")
		}

		_, found := migrationMap[requestedId]
		if !found {
			return fmt.Errorf("Requested version not found")
		}
	}

	// Next need to find all migrations HIGHER than us.
	toApply := []MigrationId{}

	for _, migrationId := range availMigrations {
		if requested != "head" && migrationId > requestedId {
			break
		}

		if migrationId > latestMigration {
			toApply = append(toApply, migrationId)
		}
	}

	for _, migrationId := range toApply {
		migration := migrationMap[migrationId]

		fullPath := migration.FullPath(manager.Directory, true)

		log.Infof("Applying migration upgrade %d - Path: %s", migrationId, fullPath)

		if pretend {
			continue
		}

		bytes, err := ioutil.ReadFile(fullPath)
		if err != nil {
			return err
		}

		strSql := string(bytes)
		if strSql == "" {
			// Empty migration is ok, we just keep going.
			continue
		}

		_, err = manager.Session.Exec(strSql)
		if err != nil {
			// Caller should rollback.
			return err
		}

		err = manager.SetVersion(migrationId)
		if err != nil {
			return err
		}

		err = manager.Session.Commit()
		if err != nil {
			return err
		}

		// Reset the session for another migration.
		err = manager.Session.Begin()
		if err != nil {
			return err
		}
	}

	return nil
}

// Are there any pending migrations?
func MigrateIsPending(manager *MigrationManager) (bool, error) {
	err := manager.CheckTable()
	if err != nil {
		return false, err
	}

	availMigrations, _, err := manager.CollectMigrations()
	if err != nil {
		return false, err
	}

	// Need to check at what migration the database is.
	latestMigration, err := manager.GetLatestMigration()
	if err != nil {
		return false, err
	}

	ret := false

	for _, migrationId := range availMigrations {
		if migrationId > latestMigration {
			log.Debugf("Pending migration: %d", migrationId)
			ret = true
			break
		}
	}

	return ret, nil
}
