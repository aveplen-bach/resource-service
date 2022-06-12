FROM golang:1.18 as builder

RUN mkdir -p /go/src/github.com/aveplen-bach/resource-service

WORKDIR /go/src/github.com/aveplen-bach/resource-service

COPY go.mod go.mod
COPY go.sum go.sum

RUN go mod download

COPY . ./

RUN CGO_ENABLED=0 go build -o /bin/resource-service \
    /go/src/github.com/aveplen-bach/resource-service/cmd/main.go

FROM alpine:3.15.4 as runtime

COPY --from=builder /bin/resource-service /bin/resource-service

ENTRYPOINT [ "/bin/resource-service" ]