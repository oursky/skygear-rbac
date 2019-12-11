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

.PHONY: setup-dev
setup-dev:
	@cp docker-compose.dev.yml docker-compose.override.yml
	@docker-compose up -d
	sleep 15
	@docker-compose down
	@go mod download

.PHONY: run-dev
run-dev:
	@DATABASE_URL=postgresql://postgres:@localhost:5432/postgres?sslmode=disable go run main.go

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
