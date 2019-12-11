package context

import (
	"database/sql"

	"github.com/casbin/casbin/v2"
)

// AppContext is used to pass services to request
type AppContext struct {
	db       *sql.DB
	Enforcer *casbin.Enforcer
}

// NewAppContext returns a new AppContext
func NewAppContext(db *sql.DB, enforcer *casbin.Enforcer) AppContext {
	return AppContext{
		db:       db,
		Enforcer: enforcer,
	}
}
