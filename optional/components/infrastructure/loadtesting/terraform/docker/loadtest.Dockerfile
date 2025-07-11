FROM golang:1.24.4-alpine3.21@sha256:56a23791af0f77c87b049230ead03bd8c3ad41683415ea4595e84ce7eada121a
ARG TAG
RUN apk add git
RUN git clone -b $TAG --depth=1 --no-tags --progress --no-recurse-submodules https://github.com/notawar/mobius.git && cd /go/mobius/cmd/osquery-perf/ && go build .

FROM alpine:3.21.3@sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c
LABEL maintainer="Mobius Developers"

# Create MobiusDM group and user
RUN addgroup -S osquery-perf && adduser -S osquery-perf -G osquery-perf

COPY --from=0 /go/mobius/cmd/osquery-perf/osquery-perf /go/osquery-perf
COPY --from=0 /go/mobius/server/vulnerabilities/testdata/ /go/mobius/server/vulnerabilities/testdata/
RUN set -eux; \
        apk update; \
        apk upgrade

USER osquery-perf
