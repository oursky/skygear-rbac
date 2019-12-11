package enforcer

import (
	"database/sql"
	"log"
	"time"

	"github.com/casbin/casbin/v2"
	casbinpgadapter "github.com/cychiuae/casbin-pg-adapter"
	"github.com/oursky/skygear-rbac/pkg/functions"
)

// Config configuration for initializing casbin Enforcer
type Config struct {
	Model     string
	File      string
	Database  string
	TableName string
}

const (
	enforcerInitializeRetryCount = 3
)

// NewEnforcer creates and return a casbin Enforcer
func NewEnforcer(enforcerConfig Config) (*casbin.Enforcer, error) {
	var enforcer *casbin.Enforcer
	var err error
	if len(enforcerConfig.Database) != 0 {
		if err != nil {
			return nil, err
		}
		db, err := func() (*sql.DB, error) {
			var err error
			for i := 0; i < enforcerInitializeRetryCount; i++ {
				db, e := sql.Open("postgres", enforcerConfig.Database)
				if e == nil {
					return db, nil
				}
				err = e
				log.Println("🔌 RBAC failed to connect db, retrying...")
				time.Sleep(time.Second)
			}
			return nil, err
		}()
		if err != nil {
			return nil, err
		}
		adapter, err := casbinpgadapter.NewAdapter(db, enforcerConfig.TableName)
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

	enforcer.EnableAutoSave(true)

	enforcer.AddFunction("isAssignedRoleInParentDomain", functions.CreateIsAssignedRoleInParentDomain(enforcer))

	return enforcer, nil
}
