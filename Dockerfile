ARG ARCH=

FROM ${ARGS}golang:1.18 AS build

WORKDIR /go/github.com/mt-inside/pem2jwks
COPY . .
RUN CGO_ENABLED=0 go install -ldflags="-extldflags=-static" .

FROM scratch AS run
COPY --from=build /go/bin/pem2jwks /
ENTRYPOINT ["/pem2jwks"]
