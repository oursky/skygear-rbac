# Alternatives considered

[← Back](/doc/README.md)

## ~~[Lodan](https://github.com/ory/ladon) (IAM-inspired)~~

> **Who** is able to do **what** on **resource** given some **context**


Terms:

* who: `Subjects`
* what: `Actions`
* resource: `Resources`
* context: `Conditions`
* allow / deny of policy matches: `Effect`

### Installation

```
import (
    . "github.com/ory/ladon"
    . "github.com/ory/ladon/manager/memory" // or other manager e.g. sql
)
```

### Usage

**1. Define policy**

```
// 1. Define Policy
var pols = []Policy{
    &DefaultPolicy{
        ID: "0",
        Description: `Interns can only update entry 123`,
        Subjects:  []string{"roles:intern"},
        Resources: []string{"hk.leighton.com:entry:123"},
        Actions:   []string{"<create|update>", "get"},
        Effect:    AllowAccess,
        Conditions: Conditions{
            "entity_id": &StringEqualCondition{
                Equals: "hk.leighton.com",
            },
        },
    },
    &DefaultPolicy{
        ID:          "1",
        Description: "This policy allows admin to update any resource",
        Subjects:    []string{"roles:admin"},
        Actions:     []string{"update"},
        Resources:   []string{"<.*>"},
        Effect:      AllowAccess,
    },
    &DefaultPolicy{
        ID:          "3",
        Description: "This policy denies admin to broadcast any of the resources",
        Subjects:    []string{"roles:admin"},
        Actions:     []string{"broadcast"},
        Resources:   []string{"<.*>"},
        Effect:      DenyAccess,
    },
}
```

**2. Add/DELETE policy dynamically**

```
warden := &Ladon{Manager: NewMemoryManager()}
warden.Manager.Create(pols[0])
warden.Manager.Delete("0")
```

**3. Ask if role have access to resource**

```
// 4. Ask if policies allow resource request
err := warden.IsAllowed(&Request{
    Subject:  "roles:intern",
    Action:   "delete",
    Resource: "hk.leighton.com:entry:123",
    Context: Context{
        "entity_id": "hk.leighton.com",
    },
})
```

### Example test file

`go test -run=TestLadon -v ./ladon_test.go`

```
package ladon_test

import (
    "fmt"
    "testing"

    "github.com/stretchr/testify/assert"

    . "github.com/ory/ladon"
    . "github.com/ory/ladon/manager/memory"
)

// 1. Define Policy
var pols = []Policy{
    &DefaultPolicy{
        ID: "0",
        Description: `Interns can only update entry 123`,
        Subjects:  []string{"roles:intern"},
        Resources: []string{"hk.leighton.com:entry:123"},
        Actions:   []string{"<create|update>", "get"},
        Effect:    AllowAccess,
        Conditions: Conditions{
            "entity_id": &StringEqualCondition{
                Equals: "hk.leighton.com",
            },
        },
    },
    &DefaultPolicy{
        ID:          "1",
        Description: "This policy allows admin to update any resource",
        Subjects:    []string{"roles:admin"},
        Actions:     []string{"update"},
        Resources:   []string{"<.*>"},
                Effect:      AllowAccess,
    },
    &DefaultPolicy{
        ID:          "3",
        Description: "This policy denies admin to broadcast any of the resources",
        Subjects:    []string{"roles:admin"},
        Actions:     []string{"broadcast"},
        Resources:   []string{"<.*>"},
        Effect:      DenyAccess,
    },
}

var cases = []struct {
    description   string
    accessRequest *Request
    expectErr     bool
}{
    {
        description: "should pass because admin is allowed to update all resources.",
        accessRequest: &Request{
            Subject:  "roles:admin",
            Action:   "update",
            Resource: "whatever.leighton.com:form:123",
        },
        expectErr: false,
    },
    {
        description: "should fail because intern cannot delete entry",
        accessRequest: &Request{
            Subject:  "roles:intern",
            Action:   "delete",
            Resource: "hk.leighton.com:entry:123",
            Context: Context{
                                "entity_id": "hk.leighton.com",
            },
        },
        expectErr: true,
    },
    {
        description: "should fail because admin cannot broadcast",
        accessRequest: &Request{
            Subject:  "roles:admin",
            Action:   "broadcast",
            Resource: "hk.leighton.com:workflow:123",
        },
        expectErr: true,
    },
}

func TestLadon(t *testing.T) {
    // 2. Instantiate ladon with the storage manager
    warden := &Ladon{Manager: NewMemoryManager()}

    // 3. Add polices dynamically.
    for _, pol := range pols {
        warden.Manager.Create(pol)
    }

    for k, c := range cases {
        t.Run(fmt.Sprintf("case=%d-%s", k, c.description), func(t *testing.T) {

            // 4. Ask if policies allow resource request
            err := warden.IsAllowed(c.accessRequest)

            assert.Equal(t, c.expectErr, err != nil)
        })
    }
}
```

### Problems

* Inheritance?  `Prefix entity_id: asia.leighton.com:hk.leighton.com` => `asia.leighton.com:.*``
* Need to map roles to user and match one-by-one manually
* Db manager is not officially supported and doesn't seem well tested
* Not really good to use entity in context

## ~~[Athenz](https://github.com/yahoo/athenz) (RBAC)~~

### Docker

```
docker pull athenz/athenz
`docker run -itd -h <server-hostname> -p 9443:9443 -p 4443:4443 -p 8443:8443 -e ZMS_SERVER=<server-hostname> -e UI_SERVER=<server-hostname> athenz/athenz`
```

### Us

```
package main

import (
  "crypto/tls"
  "flag"
  "fmt"
  "io"
  "net/http"
  "github.com/yahoo/athenz/clients/go/zms"
)

var (
  authHeader     *string*
  zmsURL         *string*
  providerDomain *string*
)

func authorizeRequest(ntoken, resource, action *string*) *bool* {
  tr := http.Transport{}
  config := &tls.Config{}
  config.InsecureSkipVerify = true
  tr.TLSClientConfig = config
  
  zmsClient := zms.ZMSClient{
    URL:       zmsURL,
    Transport: &tr,
  }
  zmsClient.AddCredentials(authHeader, ntoken)
  access, err := zmsClient.GetAccess(zms.ActionName(action), zms.ResourceName(resource), "", "")
  if err != nil {
    fmt.Printf("Unable to verify access: %v", err)
    return false
  }
  
  return access.Granted
}

func movieHandler(w http.ResponseWriter, r *http.Request) {
  // Verify if has NToken
  if r.Header[authHeader] == nil {
    http.Error(w, "403 - Missing NToken", 403)
    return
  }

  resource := providerDomain + ":rec.movie"

  if !authorizeRequest(r.Header[authHeader][0], resource, "read") {
    http.Error(w, "403 - Unauthorized access", 403)
    return
  }
  io.WriteString(w, "Name: Slap Shot; Director: George Roy Hill\n")
}

func main() {
  flag.StringVar(&zmsURL, "zms", "https://localhost:4443/zms/v1", "url of the ZMS Service")
  flag.StringVar(&authHeader, "hdr", "Athenz-Principal-Auth", "The NToken header name")
  flag.StringVar(&providerDomain, "domain", "recommend", "The provider domain name")
  flag.Parse()
  http.HandleFunc("/rec/v1/movie", movieHandler)
  http.ListenAndServe(":8080", nil)
}
```

## [Casbin](https://github.com/casbin)

### Why casbin might be better now?

**vs Lodan:**

* Entity should become a metadata rather than mandatory
* Don’t need to map user-role manually
* **OFFICIAL** db adaptor
* Can be used with Redis

**vs Athenz:**

* Can handle auth ourselves
* Might want inheritance with roles and even resources
* Modify policy in runtime easily
* Policy model can be tailored for different projects

### Usage

**Define Model + Policy**

```
[request_definition]
r = sub, obj, act # => e.Enforce(`sub, obj, act)`

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _ # group for user i.e. role

[policy_effect]
# Effect of policies.
# here means allow only if there is a policy that allow && no policies denied 
e = some(where (p.eft == allow)) && `!some(where (p.eft == deny))
`

[matchers]
# Can create custom function like entity_under: https://casbin.org/docs/en/syntax-for-models#how-to-add-a-customized-function
m = g(r.sub, p.sub) && entity_under(r.obj.entity, p.obj.entity) && r.act == p.act
```

```
p, alice, data1, read
p, bob, data2, write
p, data_group_admin, data_group, write

g, alice, data_group_admin
g2, data1, data_group
g2, data2, data_group
```

**Initialize enforcer**

```
`import`` ``"github.com/casbin/casbin"`

`e := casbin.NewEnforcer(``"path/to/model.conf"``, ``"path/to/policy.csv"``)`
```

**Enforce rule**

```
resource := &Resource{
    Name: "form:123"
`    Entity: "hk.leighton.com"`
}

if e.Enforce("alice", resource, "write") == true {
    // permit alice to read resource
} else {
    // deny the request, show an error
}
```

**Update Model dynamically**
```
`m := casbin.NewModel(`
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
`)
m.AddDef("r", "r", "sub, obj, act")
e := casbin.NewEnforcer(m, a)`
```

**Add Policy dynamically**

```
`e.AddPolicy(...)
e.RemovePolicy(...) `
```

**Register matcher function**

```
`e.AddFunction(``"entity_under"``, EntityIsUnder)`
```

### Example Test file

```
package casbin_test

import (
    "fmt"
    "testing"

    "github.com/casbin/casbin"
    "github.com/stretchr/testify/assert"
)

type Request struct {
    Subject string
    Action  string
    Object  string
}

var cases = []struct {
    description   string
    accessRequest Request
    expectPermit  bool
}{
    {
        description: "should pass because alice is allowed to write data1",
        accessRequest: Request{
            Subject: "alice",
            Action:  "write",
            Object:  "data1",
        },
        expectPermit: true,
    },
}

func TestCasbin(t *testing.T) {
    e := casbin.NewEnforcer("./model.conf", "./policy.csv")

    for k, c := range cases {
        t.Run(fmt.Sprintf("case=%d-%s", k, c.description), func(t *testing.T) {

            // 4. Ask if policies allow resource request
            permitted := e.Enforce(c.accessRequest.Subject, c.accessRequest.Object, c.accessRequest.Action)

            assert.Equal(t, c.expectPermit, permitted)
        })
    }
}
```

