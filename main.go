package main

import (
	"database/sql"
	"fmt"
	"html"
	"log"
	"net/http"
	"time"

	"github.com/casbin/casbin/v2"
	"github.com/gorilla/mux"

	"github.com/oursky/skygear-rbac/pkg/config"
	"github.com/oursky/skygear-rbac/pkg/context"
	"github.com/oursky/skygear-rbac/pkg/enforcer"
	handlers "github.com/oursky/skygear-rbac/pkg/handlers"
)

func reloadEnforcer(enforcer *casbin.Enforcer) error {
	return enforcer.LoadPolicy()
}

func main() {
	var enforcerConfig = enforcer.Config{
		Model:     "./model.conf",
		Database:  config.LoadFromEnv("DATABASE_URL", ""),
		File:      config.LoadFromEnv("POLICY_PATH", ""),
		TableName: config.LoadFromEnv("TABLE_NAME", "casbin_rule"),
	}

	if config.LoadFromEnv("ENV", "") == "development" {
		enforcerConfig = enforcer.Config{
			Model: "./model.conf",
			File:  "./policy.csv",
		}
	}

	var db *sql.DB
	if enforcerConfig.Database != "" {
		var err error
		db, err = func() (*sql.DB, error) {
			var err error
			for i := 0; i < 3; i++ {
				dbb, errr := sql.Open("postgres", enforcerConfig.Database)
				if errr == nil {
					return dbb, nil
				}
				err = errr
				log.Println("🔌 RBAC failed to connect db, retrying...")
				time.Sleep(time.Second)
			}
			return nil, err
		}()
		if err != nil {
			log.Panic(err)
		}
	}

	makeAppContext := func() (*context.AppContext, error) {
		enforcer, err := enforcer.NewEnforcer(db, enforcerConfig)
		if err != nil {
			return nil, err
		}
		appContext := context.NewAppContext(db, enforcer)
		return &appContext, nil
	}

	makeHandlerFunc := func(
		f func(appContext *context.AppContext) http.Handler,
	) func(w http.ResponseWriter, r *http.Request) {
		return func(w http.ResponseWriter, r *http.Request) {
			appContext, err := makeAppContext()
			if err != nil {
				log.Panicf("Cannot initial app context for handler %v", err)
				w.WriteHeader(502)
				return
			}
			handler := f(appContext)
			handler.ServeHTTP(w, r)
		}
	}

	r := mux.NewRouter()
	r.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, %q", html.EscapeString(r.URL.Path))
	})
	// For reloading policy / model if it is updated externally e.g. Directly updated rules in database
	r.HandleFunc("/reload", makeHandlerFunc(func(appContext *context.AppContext) http.Handler {
		return &handlers.ReloadHandler{AppContext: appContext}
	})).Methods(http.MethodPost)
	r.HandleFunc("/enforce", makeHandlerFunc(func(appContext *context.AppContext) http.Handler {
		return &handlers.EnforceHandler{AppContext: appContext}
	}))
	r.HandleFunc("/{domain}/subject/{subject}/role", makeHandlerFunc(func(appContext *context.AppContext) http.Handler {
		return &handlers.RoleHandler{AppContext: appContext}
	}))
	r.HandleFunc("/{domain}/role/{role}/policy", makeHandlerFunc(func(appContext *context.AppContext) http.Handler {
		return &handlers.PolicyHandler{AppContext: appContext}
	}))
	r.HandleFunc("/{domain}/role/{role}/subject", makeHandlerFunc(func(appContext *context.AppContext) http.Handler {
		return &handlers.SubjectHandler{AppContext: appContext}
	}))
	r.HandleFunc("/{domain}/role/{role}/user", makeHandlerFunc(func(appContext *context.AppContext) http.Handler {
		return &handlers.UserHandler{AppContext: appContext}
	}))
	r.HandleFunc("/{domain}/role", makeHandlerFunc(func(appContext *context.AppContext) http.Handler {
		return &handlers.RoleHandler{AppContext: appContext}
	}))
	r.HandleFunc("/{domain}/policy", makeHandlerFunc(func(appContext *context.AppContext) http.Handler {
		return &handlers.PolicyHandler{AppContext: appContext}
	}))
	r.HandleFunc("/{domain}", makeHandlerFunc(func(appContext *context.AppContext) http.Handler {
		return &handlers.DomainHandler{AppContext: appContext}
	}))
	r.HandleFunc("/{domain}/subdomain/{subdomain}", makeHandlerFunc(func(appContext *context.AppContext) http.Handler {
		return &handlers.DomainHandler{AppContext: appContext}
	}))

	log.Println("🚀 new RBAC listening on 6543")
	log.Fatal(http.ListenAndServe(":6543", r))
}
