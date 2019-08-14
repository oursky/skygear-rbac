.PHONY: test
test:
		go test ./...

.PHONY: dev
dev:
		ENV="development" go run main.go

.PHONY: start
start:
		go run main.go
