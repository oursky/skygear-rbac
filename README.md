# :vertical_traffic_light: RBAC service for Skygear

> NOTE: This service uses casbin as db name, all records e.g. policy, group are under casbin_rule table

## Testing

```sh
make test
```

## Docker

```sh
docker pull oursky/skygear-rbac

docker run -e "DATABASE_URL=abc" oursky/skygear-rbac:latest
```

## Current model

```golang
(
  (g(r.domain, p.domain) || g('root', r.sub)) && # request domain is SAME as policy domain (to disable inheritance of access rights)
  (
    (g2(r.sub, p.sub, r.domain) || (r.sub == p.sub && r.domain == p.domain)) || # request subject is assigned role/is the role in domain
    (g2(r.sub, p.sub, 'root') || (r.sub == p.sub && r.domain == 'root')) # request subject is assigned role/is the role in root
  )
) &&
(r.obj == p.obj || p.obj == '.*') &&  # request object matches policy
(r.act == p.act || p.act == '.*') && # request action matches policy
!g4(r.sub, 'disabled') && # subject in request is not disabled / archived
!g4(p.sub, 'disabled') # subject in policy is not disabled / archived
```
