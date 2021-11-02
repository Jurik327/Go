package migrations

type SchemaMigration struct {
	Id      int64 `xorm:"id pk autoincr"`
	Version int64 `xorm:"'version'"`
}

func (this SchemaMigration) TableName() string {
	return "schema_migrations"
}
