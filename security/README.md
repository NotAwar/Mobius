# Security

## Directory contents

- [status.md](status.md): Current status of vulnerabilities reported on Mobius software components by security scanners (trivy, docker scout). This document is currently auto-generated from files in the `vex/` directory.
- `code/`: Files used for vulnerability scanning on Mobius's source code.
- `vex/`: OpenVEX files to report status of vulnerabilities detected by Trivy on Mobius docker images.

## Vulnerability scanning

The following Github CI actions perform daily vulnerability scanning on Mobius software components.

- [trivy-scan.yml](https://github.com/notawar/mobius/blob/main/.github/workflows/trivy-scan.yml): Scan source code for vulnerabilities.
- [build-and-check-mobiuscli-docker-and-deps.yml](https://github.com/notawar/mobiuset/blob/main/.github/workflows/build-and-check-mobiuscli-docker-and-deps.yml): Scans for `HIGH` and `CRITICAL` vulnerabilities in `mobiuscli` docker image dependencies (`mobiusmdm/mobiuscli`, `mobiusmdm/wix`, and `mobiusmdm/bomutils`).
- [goreleaser-snapshot-mobius.yaml](https://github.com/notawar/mobiuset/blob/main/.github/workflows/goreleaser-snapshot-mobius.yaml): Scans for HIGH and CRITICAL vulnerabilities in `mobiusmdm/mobius` docker image before pushing to the Docker registry (runs daily and is triggered for every change in Mobius's source code).
- [check-vulnerabilities-in-released-docker-images.yml](https://github.com/notawar/mobiuset/blob/main/.github/workflows/check-vulnerabilities-in-released-docker-images.yml): Scans for `CRITICAL` vulnerabilities in the last 5 minor released versions of the `mobiusmdm/mobius` and on the latest release of `mobiusmdm/mobiuscli`.

## Process to run when a CVE is reported

### Updating status.md report

If trivy reports a `HIGH` or `CRITICAL` CVE on one of Mobius's docker images (reported by the previously mentioned Github Actions), then we need to assess the report and track it with a status of "not affected", "affected", "fixed", or "under investigation".

We use the OpenVEX format to track the status of reported vulnerabilities (`vex/` folder).

Once the status is determined, we use the [vexctl](https://github.com/openvex/vexctl) tool to create/update VEX files.

```sh
brew install vexctl
```

#### A. "Affected" status

We will use [CVE-2025-27509](https://nvd.nist.gov/vuln/detail/CVE-2025-27509) as an example.
This CVE affected all versions of Mobius at the time (see the associated [GitHub security advisory](https://github.com/notawar/mobiuset/security/advisories/GHSA-52jx-g6m5-h735)).

##### 1. Creating "affected" status

First we would need to create a VEX entry with the "affected" status for all released Mobius versions (`<= v4.63.1`).

> Currently, OpenVEX doesn't support version ranges, so we need to define all versions one by one.
> We have the `./tools/github-releases` tooling to help list all released versions of Mobius.

```sh
all_mobius_releases=$(go run ./tools/github-releases --all-cpes --separator=,)

vexctl create --product="$all_mobius_releases" \
  --vuln="CVE-2025-27509" \
  --status="affected" \
  --aliases="https://github.com/notawar/mobiuset/security/advisories/GHSA-52jx-g6m5-h735" \
  --action-statement="Disable SAML SSO authentication." \
  --author="@lucasmrod" > security/vex/mobius/CVE-2025-27509.vex.json
```

##### 2. Updating "fixed" status

Once the fix was released in `v4.64.2`, `v4.63.2`, `v4.62.4`, `v4.58.1` and `v4.53.2` we would issue a new "fixed" statement on the existing VEX document:

```sh
vexctl add \
  --document=./security/vex/mobius/CVE-2025-27509.vex.json \
  --vuln="CVE-2025-27509" \
  --status="fixed" \
  --product="cpe:2.3:a:mobiusmdm:mobius:v4.64.2:*:*:*:*:*:*:*,cpe:2.3:a:mobiusmdm:mobius:v4.63.2:*:*:*:*:*:*:*,cpe:2.3:a:mobiusmdm:mobius:v4.62.4:*:*:*:*:*:*:*,cpe:2.3:a:mobiusmdm:mobius:v4.58.1:*:*:*:*:*:*:*,cpe:2.3:a:mobiusmdm:mobius:v4.53.2:*:*:*:*:*:*:*" \
  --aliases="https://github.com/notawar/mobiuset/security/advisories/GHSA-52jx-g6m5-h735" \
  --in-place
```

#### B. Not affected

Following is an example for a CVE reported by tooling which we know doesn't affect `mobiusmdm/mobiuscli`:

Example for `CVE-2023-32698` on package `github.com/goreleaser/nfpm/v2` which we know doesn't affect `mobiusmdm/mobiuscli`:

```sh
vexctl create --product="mobiuscli,pkg:golang/github.com/goreleaser/nfpm/v2" \
  --vuln="CVE-2023-32698" \
  --status="not_affected" \
  --author="@getvictor" \
  --justification="vulnerable_code_cannot_be_controlled_by_adversary" \
  --status-note="When packaging linux files, mobiuscli does not use global permissions. It was verified that packed mobiusdaemon package files do not have group/global write permissions." > security/vex/mobiuscli/CVE-2023-32698.vex.json
```

Similarly, for `CVE-2024-8260` on package `github.com/open-policy-agent/opa` which we know doesn't affect `mobiusmdm/mobius`:

```sh
vexctl create --product="mobius,pkg:golang/github.com/open-policy-agent/opa" \
  --vuln="CVE-2024-8260" \
  --status="not_affected" \
  --author="@lucasmrod" \
  --justification="vulnerable_code_cannot_be_controlled_by_adversary" \
  --status-note="Mobius doesn't run on Windows, so it's not affected by this vulnerability." > security/vex/mobiuscli/CVE-2024-8260.vex.json
```

Examples of `--product` flag values (which accept "PURLs"):

- `liblzma5` debian package: `pkg:deb/debian/liblzma5`.
- `github.com/goreleaser/nfpm/v2` golang package: `pkg:golang/github.com/goreleaser/nfpm/v2`.
- `xerces/xercesImpl` java package: `pkg:maven/xerces/xercesImpl`.

When new VEX files are generated or updated we can update the `security/status.md` file by running:

```sh
make vex-report
```

### Updating software

If the detected vulnerability can be fixed by updating the base docker image or removing/changing components in the docker image then we do so and the update will be present on the next release. (It is good practice to keep software up-to-date.)

### Process for "affected" CRITICAL vulnerabilities

#### mobiusmdm/mobius

Following is the process to run when a `CRITICAL` CVE affects any of the five last releases of `mobiusmdm/mobius` docker image (reported by [check-vulnerabilities-in-released-docker-images.yml](https:github.com/notawar/mobiusleet/blob/main/.github/workflows/check-vulnerabilities-in-released-docker-images.yml)).

1. We will use the information reported by the scanner and update our `status.md` to keep users/customers informed.
2. If the `CRITICAL` vulnerability (that has a fix) is on the `latest` release, we'll file a critical/P0 bug and release a patch ASAP (within 1 business day). The previous four versions scanned won't be retroactively patched, only `latest` will be patched.

#### mobiusmdm/mobiuscli

Following is the process to run when a `CRITICAL` CVE affects the released `mobiusmdm/mobiuscli:latest` docker image:

1. After `security/status.md` is updated, notify users/customers about the CVE in the `mobiusmdm/mobiuscli` image and possible remediations.
2. Create a Github issue with a `P0`/`security` label to track the fix.
3. The fix will be released on the next release of the `mobiusmdm/mobiuscli` docker image.
