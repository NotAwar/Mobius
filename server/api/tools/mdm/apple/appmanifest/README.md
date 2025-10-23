## appmanifest

`appmanifest` is a tool that outputs to stdout a valid XML manifest that can be used by the MDM `InstallEnterpriseApplication` command to install a package.

```
$ go run tools/mdm/apple/appmanifest/main.go --help
Usage of appmanifest:
  -pkg-file string
     Path to a .pkg file
  -pkg-url string
     URL where the package will be served
```

### Example workflow

1. Create a mobiusdaemon installer

```
mobiuscli package --type=pkg --mobius-desktop
```

2. Sign the installer so it can be installed via MDM

```
productsign --sign "Developer ID Installer: $DEVID_INFO" mobius-osquery.pkg mobiusdaemon-base.pkg
```

3. Run `appmanifest`

```
$ go run tools/mdm/apple/appmanifest/main.go \
    -pkg-file mobiusdaemon-base.pkg \
    -pkg-url $YOUR_URL > mobiusdaemon-base-manifest.plist
```

4. Upload `mobiusdaemon-base.pkg` to `$YOUR_URL` and `mobiusdaemon-base-manifest.plist` to a publicly accessible location.
