FROM golang:1.12.5-stretch as godev

ENV GO111MODULE on

WORKDIR /go/src/github.com/skygeario/skygear-server

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN cd cmd/rbac; make build; mv skygear-rbac /tmp/

FROM alpine:3.8

RUN apk add --update --no-cache libc6-compat ca-certificates && \
    ln -s /lib /lib64

COPY --from=godev /tmp/skygear-rbac /
RUN chmod a+x /skygear-rbac
USER nobody

EXPOSE 3000

CMD ["/skygear-rbac"]
