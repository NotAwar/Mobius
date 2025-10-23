FROM golang:1.25.3-alpine
ARG TAG
RUN apk update && apk add --no-cache git
RUN git clone -b $TAG --depth=1 --no-tags --progress --no-recurse-submodules https://github.com/notawar/mobius.git && cd /go/mobius/tools/mdm/migration/mdmproxy && go build .

FROM alpine:3.20@sha256:b3119ef930faabb6b7b976780c0c7a9c1aa24d0c75e9179ac10e6bc9ac080d0d
LABEL maintainer="Mobius Developers"

RUN apk update && apk add --no-cache tini
COPY --from=0 /go/mobius/tools/mdm/migration/mdmproxy/mdmproxy /usr/bin/mdmproxy
ADD --chmod=0755 ./entrypoint.sh /usr/bin/entrypoint.sh

# Create mdmproxy group and user
RUN addgroup -S mdmproxy && adduser -S mdmproxy -G mdmproxy
USER mdmproxy

ENTRYPOINT ["/sbin/tini", "/usr/bin/entrypoint.sh"]
