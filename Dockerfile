FROM golang:1.12.5 as builder

ARG GIT_COMMIT=unspecified
LABEL git_commit=$GIT_COMMIT

WORKDIR /src/rbac

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN GOARCH=amd64 GOOS=linux CGO_ENABLED=0 go build -o /tmp/rbac
COPY ./model.conf ./policy.csv /tmp/

FROM scratch

ENV DATABASE_URL postgres://postgres:@db?sslmode=disable

WORKDIR /

COPY --from=builder /tmp/ /

ENTRYPOINT ["/rbac"]
