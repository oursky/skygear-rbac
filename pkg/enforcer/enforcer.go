package enforcer

import (
	"database/sql"
	"log"

	"github.com/casbin/casbin/v2"
	casbinpgadapter "github.com/cychiuae/casbin-pg-adapter"
	"github.com/oursky/skygear-rbac/pkg/config"
	"github.com/oursky/skygear-rbac/pkg/functions"
)

// Config configuration for initializing casbin Enforcer
type Config struct {
	Model     string
	File      string
	Database  string
	TableName string
}

// NewEnforcerConfigFromConfig create enforcer config from confi
func NewEnforcerConfigFromConfig(appConfig config.Config) Config {
	return Config{
		Model:     appConfig.Model,
		File:      appConfig.File,
		Database:  appConfig.Database,
		TableName: appConfig.TableName,
	}
}

// NewEnforcer creates and return a casbin Enforcer
func NewEnforcer(db *sql.DB, enforcerConfig Config) (*casbin.Enforcer, error) {
	var enforcer *casbin.Enforcer
	var err error
	if db != nil {
		adapter, err := casbinpgadapter.NewAdapter(db, enforcerConfig.TableName)
		if err != nil {
			return nil, err
		}

		enforcer, err = casbin.NewEnforcer(enforcerConfig.Model, adapter)
		if err != nil {
			return nil, err
		}
	} else if len(enforcerConfig.File) != 0 {
		log.Printf("📒 RBAC is using CSV storage %s \n", enforcerConfig.File)
		enforcer, err = casbin.NewEnforcer(enforcerConfig.Model, enforcerConfig.File)
		if err != nil {
			return nil, err
		}
	} else {
		log.Println("🧠 RBAC does not detect any storage setting, using In-Memory")
		enforcer, err = casbin.NewEnforcer(enforcerConfig.Model)
		if err != nil {
			return nil, err
		}
	}
	enforcer.LoadPolicy()
	enforcer.EnableAutoSave(true)
	enforcer.AddFunction(
		"isAssignedRoleInParentDomain",
		functions.CreateIsAssignedRoleInParentDomain(enforcer),
	)
	return enforcer, nil
}
