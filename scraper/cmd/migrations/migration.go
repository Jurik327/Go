package migrations

import (
	"path/filepath"
)

type Migration struct {
	MigrationId MigrationId
	Prefix      string
	PreviousId  MigrationId
}

func (m Migration) FullPath(migrationDir string, upgrade bool) string {
	name := m.Prefix
	if upgrade {
		name += "_up.sql"
	} else {
		name += "_down.sql"
	}

	return filepath.Join(migrationDir, name)
}
