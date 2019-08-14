FROM golang:1.12.5 as builder

ENV GO111MODULE on

WORKDIR /go/src/rbac

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN GOARCH=amd64 GOOS=linux CGO_ENABLED=0 go build -o /tmp/rbac
COPY ./model.conf ./policy.csv /tmp/

FROM scratch

WORKDIR /

COPY --from=builder /tmp/ /

ENTRYPOINT ["/rbac"]
