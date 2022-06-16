# Theory: either need --platform=BUILDPLATFORM (ie always use the build host's toolchain) AND then tell golang to cross-compile, or neither...
# - ie either run the native build image both times and get it to cross-compile one of the time, OR
# - run native->nativce compile both times, once under emulation
# Choice: run the targets' compilers, cause go gets funny about cross-compilation if we ever have to turn CGO back on
# Ref: https://www.docker.com/blog/faster-multi-platform-builds-dockerfile-cross-compilation-guide/
FROM golang:1.18 AS build

WORKDIR /go/github.com/mt-inside/pem2jwks
COPY . .
RUN CGO_ENABLED=0 go install -ldflags="-extldflags=-static" .

FROM scratch AS run
COPY --from=build /go/bin/pem2jwks /
ENTRYPOINT ["/pem2jwks"]
