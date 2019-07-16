# Model

**Model** describes what arguments are provided, how a policy is interpreted and how to make conclusion based on policies.

**Example RBAC Model**

```yaml
[request_definition]
r = sub, obj, act # => e.Enforce(sub, obj, act)

[policy_definition]
p = sub, obj, act # Shape of a policy rule

[role_definition]
g = _, _ # group for user i.e. role

[policy_effect]
# Effect of policies.
# here means to permit if and only if there is a policy that allow && no policies denied it
e = some(where (p.eft == allow)) && !some(where (p.eft == deny))

[matchers]
# Can create custom function like entity_under: https://casbin.org/docs/en/syntax-for-models#how-to-add-a-customized-function
m = g(r.sub, p.sub) && entity_under(r.obj.entity, p.obj.entity) && r.act == p.act
```
