# Test Orbit mTLS

> WARNING: All of these scripts are for testing only, they are not safe for production use.

Following is a guide to help you run and test Orbit with TLS client certificate authentication.

All commands are executed in the repository's root directory.
All commands were tested on an Intel macOS.

## Diagram of components

```mermaid
graph LR;
    tuf[TUF file server<br>http://host.docker.internal:8081];
    mobius_server[Mobius Server<br>https://host.docker.internal:8080];
    subgraph nginx[<b>nginx</b> https://host.docker.internal:8888]
        client_ca[client_ca.crt];
        server_certificate_nginx[mobius.pem];
    end
    nginx -- TLS Mobius --> mobius_server;
    nginx -- HTTP /tuf --> tuf;

    subgraph mobiusdaemon
        subgraph orbit
            mobius_client_certificate_orbit[mobius_client.crt<br>mobius_client.key];
            update_client_certificate_orbit[update_client.crt<br>update_client.key];
            mobius_server_certificate_orbit[mobius.pem];
            update_server_certificate_orbit[update.pem];
        end
        subgraph desktop [Mobius Desktop]
            client_certificate_desktop["(from env)<br>mobius_client.crt<br>mobius_client.key"];
            server_certificate_desktop["(from env)<br>mobius.pem"];
        end
        subgraph osquery[osquery];
            client_certificate_osquery[--tls_client_cert=mobius_client.crt<br>--tls_client_key=mobius_client.key];
            server_certificate_osquery[--tls_server_certs=mobius.pem];
        end

        desktop_browser[Mobius Desktop<br> from Browser];
    end

    orbit -- "Mobius Orbit API (TLS)" --> nginx;
    desktop -- "Mobius Desktop API (TLS)" --> nginx;
    osquery -- "osquery<br>remote API (TLS)" --> nginx;
    desktop_browser -- "My Device URL (TLS)" --> mobius_server;

    orbit -- TUF TLS --> nginx;

    subgraph mobiuscli[mobiuscli package command]
        update_client_certificate_mobiuscli[update_client.crt<br>update_client.key];
    end
    mobiuscli -- TUF TLS --> nginx;
```

The nginx proxy is configured to authenticate all TLS requests with the provided `client_ca.crt`.

## 1. Setup

This guide assumes the following [Local TUF setup](../tuf/test/README.md#setup).

## 2. Start nginx proxy with client certificate verification

```sh
docker compose -f ./tools/test-orbit-mtls/docker-compose.yml up
```

The proxy will listen to port 8888 and use TLS client certificates for authentication.

## 3. Generate Orbit installers with custom flags

```sh
rm -rf test_tuf

SYSTEMS="macos windows linux" \
PKG_MOBIUS_URL=https://host.docker.internal:8888 \
PKG_TUF_URL=https://host.docker.internal:8888/tuf \
DEB_MOBIUS_URL=https://host.docker.internal:8888 \
DEB_TUF_URL=https://host.docker.internal:8888/tuf \
RPM_MOBIUS_URL=https://host.docker.internal:8888 \
RPM_TUF_URL=https://host.docker.internal:8888/tuf \
MSI_MOBIUS_URL=https://host.docker.internal:8888 \
MSI_TUF_URL=https://host.docker.internal:8888/tuf \
GENERATE_PKG=1 \
GENERATE_DEB=1 \
GENERATE_RPM=1 \
GENERATE_MSI=1 \
ENROLL_SECRET=OokY/M85nibwa3WjDtC091QzXqkoVCwX \
MOBIUS_DESKTOP=1 \
USE_MOBIUS_SERVER_CERTIFICATE=1 \
USE_MOBIUS_CLIENT_CERTIFICATE=1 \
USE_UPDATE_SERVER_CERTIFICATE=1 \
USE_UPDATE_CLIENT_CERTIFICATE=1 \
MOBIUS_DESKTOP_ALTERNATIVE_BROWSER_HOST=host.docker.internal:8080 \
./tools/tuf/test/main.sh
```

We need to define `MOBIUS_DESKTOP_ALTERNATIVE_BROWSER_HOST` because we are not expecting users to configure client certificates on their browser.

Once the packages are generated, they are ready to be installed on devices for testing.
