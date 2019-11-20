package enforcer

import (
	"log"
	"skygear-rbac/config"
	"time"

	"github.com/casbin/casbin/v2"
	xormadapter "github.com/casbin/xorm-adapter"
	"github.com/lib/pq"
)

// Config configuration for initializing casbin Enforcer
type Config struct {
	Model  string
	Policy string
}

const (
	enforcerInitializeRetryCount = 3
)

// NewEnforcer creates and return a casbin Enforcer
func NewEnforcer(enforcerConfig Config) (*casbin.Enforcer, error) {
	var enforcer *casbin.Enforcer
	var err error
	if config.LoadFromEnv("ENV", "") == "development" {
		if enforcerConfig.Policy != "" {
			enforcer, err = casbin.NewEnforcer(enforcerConfig.Model, enforcerConfig.Policy)
			if err != nil {
				return nil, err
			}
		} else {
		enforcer, err = casbin.NewEnforcer(enforcerConfig.Model)
		if err != nil {
			return nil, err
		}
		}
	} else {
		databaseURL := config.LoadFromEnv("DATABASE_URL", "postgres://postgres:@db?sslmode=disable")
		params, err := pq.ParseURL(databaseURL)
		if err != nil {
			return nil, err
		}
		adapter, err := func() (*xormadapter.Adapter, error) {
			var err error
			for i := 0; i < enforcerInitializeRetryCount; i++ {
				a, e := xormadapter.NewAdapter("postgres", params)
				if e == nil {
					return a, nil
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
		enforcer, err = casbin.NewEnforcer(enforcerConfig.Model, adapter)
		if err != nil {
			return nil, err
		}
	}

	return enforcer, nil
}
