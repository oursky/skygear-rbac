NAME	 := oursky/skygear-rbac
TAG    := $(shell git rev-parse --short HEAD)
IMG		 := ${NAME}:${TAG}
LATEST := ${NAME}:latest

.PHONY: test
test:
		ENV="development" go test ./...

.PHONY: dev
dev:
		ENV="development" go run main.go

.PHONY: start
start:
		go run main.go

.PHONY: docker-build
docker-build:
		docker build -t ${IMG} . --build-arg GIT_COMMIT=${TAG}
		docker tag ${IMG} ${LATEST}

.PHONY: docker-push
docker-push:
		docker push ${NAME}
