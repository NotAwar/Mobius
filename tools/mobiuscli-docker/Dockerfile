FROM rust:latest@sha256:563b33de55d0add224b2e301182660b59bf3cf7219e9dc0fda68f8500e5fe14a AS builder

ARG transporter_url=https://itunesconnect.apple.com/WebObjects/iTunesConnect.woa/ra/resources/download/public/Transporter__Linux/bin

RUN cargo install --locked --version 0.28.0 apple-codesign \
  && curl -sSf $transporter_url -o transporter_install.sh \
  && sh transporter_install.sh --target transporter --accept --noexec

FROM debian:stable-slim@sha256:e5365b94db65754594422a8a101c873728711c6a4df029677f4a7f7200d6e1c3

ARG binpath=build/binary-bundle/linux/mobiuscli

RUN apt-get update \
  && dpkg --add-architecture i386 \
  && apt update \
  && apt upgrade -y \
  && apt install -y --no-install-recommends ca-certificates cpio libxml2 wine wine32 libgtk-3-0 \
  && rm -rf /var/lib/apt/lists/* 

# copy macOS dependencies
COPY --from=mobiusmdm/bomutils:latest /usr/bin/mkbom /usr/local/bin/xar /usr/bin/
COPY --from=mobiusmdm/bomutils:latest /usr/local/lib /usr/local/lib/
COPY --from=builder /transporter/itms /usr/local/
COPY --from=builder /usr/local/cargo/bin/rcodesign /usr/local/bin

# copy Windows dependencies
COPY --from=mobiusmdm/wix:latest /home/wine /home/wine

# copy mobiuscli
COPY ${binpath} /usr/bin/mobiuscli

ENV MOBIUSCTL_NATIVE_TOOLING=1 WINEPREFIX=/home/wine/.wine WINEARCH=win32 PATH="/home/wine/bin:$PATH" WINEDEBUG=-all

ENTRYPOINT ["mobiuscli"]
