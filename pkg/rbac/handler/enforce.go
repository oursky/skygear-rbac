package handler

import (
	"encoding/json"
	"net/http"

	"github.com/skygeario/skygear-server/pkg/auth/dependency/provider/password"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/userprofile"
	coreAuth "github.com/skygeario/skygear-server/pkg/core/auth"
	"github.com/skygeario/skygear-server/pkg/core/auth/authinfo"
	"github.com/skygeario/skygear-server/pkg/core/auth/authtoken"
	"github.com/skygeario/skygear-server/pkg/core/auth/authz"
	"github.com/skygeario/skygear-server/pkg/core/auth/authz/policy"
	"github.com/skygeario/skygear-server/pkg/core/db"
	"github.com/skygeario/skygear-server/pkg/core/handler"
	"github.com/skygeario/skygear-server/pkg/core/inject"
	"github.com/skygeario/skygear-server/pkg/core/server"
	"github.com/skygeario/skygear-server/pkg/core/skyerr"
	"github.com/skygeario/skygear-server/pkg/rbac"
	"github.com/skygeario/skygear-server/pkg/rbac/response"
)

func AttachEnforceHandler(
	server *server.Server,
	rbacDependency rbac.DependencyMap,
) *server.Server {
	server.Handle("/enforce", &EnforceHandlerFactory{
		rbacDependency,
	}).Methods("OPTIONS", "POST")
	return server
}

type EnforceRequestPayload struct {
	UserID string `json:"user_id"`
	Action string `json:"action"`
	Object string `json:"object"`
}

func (p EnforceRequestPayload) Validate() error {
	if p.UserID == "" {
		return skyerr.NewInvalidArgument("empty user id", []string{"user_id"})
	}
	if p.Action == "" {
		return skyerr.NewInvalidArgument("empty action", []string{"action"})
	}
	if p.Object == "" {
		return skyerr.NewInvalidArgument("empty object", []string{"object"})
	}
	return nil
}

type EnforceHandlerFactory struct {
	Dependency rbac.DependencyMap
}

func (f EnforceHandlerFactory) NewHandler(request *http.Request) http.Handler {
	h := &EnforceHandler{}
	inject.DefaultRequestInject(h, f.Dependency, request)
	return handler.APIHandlerToHandler(h, h.TxContext)
}

func (f EnforceHandlerFactory) ProvideAuthzPolicy() authz.Policy {
	return policy.AllOf(
		authz.PolicyFunc(policy.DenyNoAccessKey),
		authz.PolicyFunc(policy.RequireAuthenticated),
		authz.PolicyFunc(policy.DenyDisabledUser),
	)
}

// EnforceHandler handles method of the me request, responds with current user data.
//
// The handler also:
// 1. refresh access token with a newly generated one
// 2. populate the activity time to user
//
//  curl -X POST -H "Content-Type: application/json" \
//    -d @- http://localhost:3000/enforce <<EOF
//  {
//     "user_id": "",
// 		 "action": "",
// 		 "object": ""
//  }
//  EOF
//
// {
//   "permitted": true
// }
type EnforceHandler struct {
	AuthContext          coreAuth.ContextGetter `dependency:"AuthContextGetter"`
	TxContext            db.TxContext           `dependency:"TxContext"`
	TokenStore           authtoken.Store        `dependency:"TokenStore"`
	AuthInfoStore        authinfo.Store         `dependency:"AuthInfoStore"`
	UserProfileStore     userprofile.Store      `dependency:"UserProfileStore"`
	PasswordAuthProvider password.Provider      `dependency:"PasswordAuthProvider"`
}

func (h EnforceHandler) WithTx() bool {
	return true
}

func (h EnforceHandler) DecodeRequest(request *http.Request) (handler.RequestPayload, error) {
	payload := EnforceRequestPayload{}
	err := json.NewDecoder(request.Body).Decode(&payload)
	return payload, err
}

func (h EnforceHandler) Handle(req interface{}) (resp interface{}, err error) {
	// payload := req.(EnforceRequestPayload)

	// token, err := h.TokenStore.NewToken(authInfo.ID)
	// if err != nil {
	// 	panic(err)
	// }

	// if err = h.TokenStore.Put(&token); err != nil {
	// 	panic(err)
	// }

	// // Get Profile
	// var userProfile userprofile.UserProfile
	// if userProfile, err = h.UserProfileStore.GetUserProfile(authInfo.ID); err != nil {
	// 	// TODO:
	// 	// return proper error
	// 	err = skyerr.NewError(skyerr.UnexpectedError, "Unable to fetch user profile")
	// 	return
	// }

	respFactory := response.RBACResponseFactory{}
	resp = respFactory.RBACResponse(true)

	return
}
