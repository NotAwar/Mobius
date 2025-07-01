# Upgrading Mobius

This guide explains how to upgrade your Mobius instance to the latest version in order to get the latest features and bug fixes. For initial installation instructions, see [Installing Mobius](https://mobiusmdm.com/docs/deploy/deploy-mobius-on-centos#installing-mobius).

There are four steps to perform a typical Mobius upgrade:

1. [Bringing Mobius offline](#bring_mobius_offline)
2. [Installing the latest version](#install-the-latest-version-of-mobius)
3. [Preparing the database](#prepare-the-database)
4. [Serving the new Mobius instance](#serve-the-new-version)

## Bring Mobius offline

In order to avoid any errors while preparing the database for the new version of Mobius, all Mobius instances need to be shut down during the migration process. During a typical upgrade, you can expect 5-10 minutes
of downtime.

> Your hosts will buffer any logs generated during this time and send those buffered logs once the server is brought online again.

## Install the latest version of Mobius

Mobius may be installed locally, or used in a Docker container. Follow the appropriate method for your environment.

### Local installation

[Download](https://github.com/notawar/mobius/releases) the latest version of Mobius. Check the `Upgrading` section of the release notes for any additional steps that may need to be taken for a specific release.

Unzip the newly downloaded version, and replace the existing Mobius version with the new, unzipped version.

For example, after downloading:

```sh
unzip mobius.zip 'linux/*' -d mobius
sudo cp mobius/linux/mobius* /usr/bin/
```

### Docker container

Pull the latest Mobius docker image:

```sh
docker pull mobiusmdm/mobius
```

## Prepare the database

Changes to Mobius may include changes to the database. Running the built-in database migrations will ensure that your database is set up properly for the currently installed version.

It is always advised to [back up the database](https://dev.mysql.com/doc/refman/8.0/en/backup-methods.html) before running migrations.

Database migrations in Mobius are intended to be run while the server is offline. Osquery is designed to be resilient to short downtime from the server, so no data will be lost from `osqueryd` clients in this process. Even on large Mobius installations, downtime during migrations is usually only seconds to minutes.

Run database migrations:

```sh
mobius prepare db
```

## Serve the new version

Once Mobius has been replaced with the newest version and the database migrations have completed, serve the newly upgraded Mobius instance:

```sh
mobius serve
```

## AWS with Terraform

If you are using Mobius's Terraform modules to manage your Mobius deployment to AWS, update the version in `main.tf`:

```tf
  mobius_config = {
    image = "mobiusmdm/mobius:<version>" 
    [...]
  }
```

Run `terraform apply` to apply the changes.

<meta name="pageOrderInSection" value="300">
<meta name="description" value="Learn how to upgrade your Mobius instance to the latest version.">
