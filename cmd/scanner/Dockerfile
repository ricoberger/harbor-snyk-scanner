FROM golang:1.17.3-alpine3.14 as build
RUN apk update && apk add git make
WORKDIR /scanner
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN export CGO_ENABLED=0 && make build

FROM alpine:3.14.2
RUN apk update && apk add --no-cache ca-certificates
RUN mkdir /scanner
COPY --from=build /scanner/bin/scanner /scanner
WORKDIR /scanner
USER nobody
ENTRYPOINT  [ "/scanner/scanner" ]
