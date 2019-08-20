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
