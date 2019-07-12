# :vertical_traffic_light: RBAC Gear for Skygear

## Setup (for now)

1. Soft link RBAC into [skygear-server@next](https://github.com/SkygearIO/skygear-server/tree/next/)
  ```sh
  ln -s ${pwd}/cmd/rbac ${GOPATH}/skygear-server/cmd/rbac
  ln -s ${pwd}/pkg/rbac ${GOPATH}/skygear-server/pkg/rbac
  ```

2. Apply [RBAC patch](https://gist.github.com/IniZio/766e55c522cec3e673e4063e19b7dd7c) into skygear-server
  ```sh
  git apply rbac.patch
  ```

3. Build RBAC gear image in skygear-server
  ```sh
  make build docker-build-rbac
  ```
  
4. Clone git@github.com:IniZio/demo-skygear-rbac.git
  ```sh
  make setup
  docker-compose up
  ```
