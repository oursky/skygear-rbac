package main

import (
	"context"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/skygeario/skygear-server/pkg/core/auth/authn/resolver"
	"github.com/skygeario/skygear-server/pkg/rbac"

	"github.com/kelseyhightower/envconfig"

	"github.com/joho/godotenv"
	"github.com/skygeario/skygear-server/pkg/core/config"
	"github.com/skygeario/skygear-server/pkg/core/logging"
	"github.com/skygeario/skygear-server/pkg/core/middleware"
	"github.com/skygeario/skygear-server/pkg/core/server"
	"github.com/skygeario/skygear-server/pkg/rbac/handler"
)

type configuration struct {
	Standalone                        bool
	StandaloneTenantConfigurationFile string `envconfig:"STANDALONE_TENANT_CONFIG_FILE" default:"standalone-tenant-config.yaml"`
	PathPrefix                        string `envconfig:"PATH_PREFIX"`
	Host                              string `default:"localhost:3000"`
}

func main() {
	envErr := godotenv.Load()
	if envErr != nil {
		log.Print("Error in loading .env file")
	}

	configuration := configuration{}
	envconfig.Process("", &configuration)

	// default template initialization
	// templateEngine := template.NewEngine()
	// authTemplate.RegisterDefaultTemplates(templateEngine)

	// logging initialization
	logging.SetModule("rbac")

	// asyncTaskExecutor := async.NewExecutor()
	rbacDependency := rbac.DependencyMap{}

	authContextResolverFactory := resolver.AuthContextResolverFactory{}

	var srv server.Server
	if configuration.Standalone {
		filename := configuration.StandaloneTenantConfigurationFile
		tenantConfig, err := config.NewTenantConfigurationFromYAMLAndEnv(func() (io.Reader, error) {
			return os.Open(filename)
		})
		if err != nil {
			log.Fatal(err)
		}

		serverOption := server.DefaultOption()
		serverOption.GearPathPrefix = configuration.PathPrefix
		srv = server.NewServerWithOption(configuration.Host, authContextResolverFactory, serverOption)
		srv.Use(middleware.TenantConfigurationMiddleware{
			ConfigurationProvider: middleware.ConfigurationProviderFunc(func(_ *http.Request) (config.TenantConfiguration, error) {
				return *tenantConfig, nil
			}),
		}.Handle)
	} else {
		srv = server.NewServer(configuration.Host, authContextResolverFactory)
	}

	srv.Use(middleware.RequestIDMiddleware{}.Handle)
	srv.Use(middleware.CORSMiddleware{}.Handle)

	handler.AttachEnforceHandler(&srv, rbacDependency)
	// handler.AttachSignupHandler(&srv, rbacDependency)
	// handler.AttachLoginHandler(&srv, rbacDependency)
	// handler.AttachLogoutHandler(&srv, rbacDependency)
	// handler.AttachMeHandler(&srv, rbacDependency)
	// handler.AttachSetDisableHandler(&srv, rbacDependency)
	// handler.AttachChangePasswordHandler(&srv, rbacDependency)
	// handler.AttachResetPasswordHandler(&srv, rbacDependency)
	// handler.AttachWelcomeEmailHandler(&srv, rbacDependency)
	// handler.AttachUpdateMetadataHandler(&srv, rbacDependency)
	// forgotpwdhandler.AttachForgotPasswordHandler(&srv, rbacDependency)
	// forgotpwdhandler.AttachForgotPasswordResetHandler(&srv, rbacDependency)
	// userverifyhandler.AttachVerifyRequestHandler(&srv, rbacDependency)
	// userverifyhandler.AttachVerifyCodeHandler(&srv, rbacDependency)
	// ssohandler.AttachAuthURLHandler(&srv, rbacDependency)
	// ssohandler.AttachConfigHandler(&srv, rbacDependency)
	// ssohandler.AttachIFrameHandlerFactory(&srv, rbacDependency)
	// ssohandler.AttachCustomTokenLoginHandler(&srv, rbacDependency)
	// ssohandler.AttachAuthHandler(&srv, rbacDependency)
	// ssohandler.AttachProviderProfilesHandler(&srv, rbacDependency)
	// ssohandler.AttachLoginHandler(&srv, rbacDependency)
	// ssohandler.AttachLinkHandler(&srv, rbacDependency)
	// ssohandler.AttachUnlinkHandler(&srv, rbacDependency)

	go func() {
		log.Printf("RBAC gear boot")
		if err := srv.ListenAndServe(); err != nil {
			log.Println(err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	// wait interrupt signal
	select {
	case <-sig:
		log.Printf("Stoping http server ...\n")
	}

	// create shutdown context with 10 second timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// shutdown the server
	err := srv.Shutdown(ctx)
	if err != nil {
		log.Printf("Shutdown request error: %v\n", err)
	}
}
