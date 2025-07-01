# Reference architectures

## The Mobius binary

The Mobius application contains two single static binaries which provide web based administration, a REST API, and a [CLI interface](https://mobiusmdm.com/guides/mobiuscli).

The `mobius` binary contains:

- The [Mobius TLS web server](https://mobiusmdm.com/docs/configuration/mobius-server-configuration) (no external webserver is required but it supports a proxy if desired)
- The Mobius web interface
- The Mobius application management [REST API](https://mobiusmdm.com/docs/using-mobius/rest-api)
- The Mobius osquery API endpoints

The `mobiuscli` binary is the CLI interface which allows management of your deployment, scriptable live queries, and easy integration into your existing logging, alerting, reporting, and management infrastructure.

Both binaries are available for download from our [repo](https://github.com/notawar/mobius/releases).

Once you've downloaded the binaries, extract the files to your desired location:

```
tar -xf mobius_v*_linux.tar.gz # Extract the Mobius binary
sudo cp mobius_v*_linux/mobius /usr/bin/ # Copy the the Mobius binary to /usr/bin
mobius version # Sanity check to make sure it runs as expected
```

## Infrastructure dependencies

Mobius currently has three infrastructure dependencies: MySQL, Redis, and a TLS certificate.

![Mobius's architecture diagram](https://raw.githubusercontent.com/mobiusmdm/mobius/main/docs/images/mobius-architecture-diagram.png)

### MySQL

Mobius uses MySQL extensively as its main database. Many cloud providers (such as [AWS](https://aws.amazon.com/rds/mysql/) and [GCP](https://cloud.google.com/sql/)) host reliable MySQL services which you may consider for this purpose. A well-supported MySQL [Docker image](https://hub.docker.com/_/mysql/) also exists if you would rather run MySQL in a container.
For more information on how to configure the `mobius` binary to use the correct MySQL instance, see the [MySQL configuration](https://mobiusmdm.com/docs/configuration/mobius-server-configuration#mysql) documentation.

Mobius requires at least MySQL version 8.0.36, and is tested using the InnoDB storage engine [with versions 8.0.36, 8.4.5, and 9.3.0](https://github.com/notawar/mobius/blob/main/.github/workflows/test-go.yaml#L47).

There are many "drop-in replacements" for MySQL available. If you'd like to experiment with some bleeding-edge technology and use Mobius with one of these alternative database servers, we think that's awesome! Please be aware they are not officially supported and that it is very important to set up a dev environment to thoroughly test new releases.

> If you use multiple databases per database server for multiple Mobius instances, you'll need to provision more resources for your database server to ensure performance. You can experiment with finding the right resourcing for your needs.

### Redis

Mobius uses Redis to ingest and queue the results of distributed queries, cache data, etc. Many cloud providers (such as [AWS](https://aws.amazon.com/elasticache/) and [GCP](https://console.cloud.google.com/launcher/details/click-to-deploy-images/redis)) host reliable Redis services which you may consider for this purpose. A well supported Redis [Docker image](https://hub.docker.com/_/redis/) also exists if you would rather run Redis in a container. For more information on how to configure the `mobius` binary to use the correct Redis instance, see the [Redis configuration](https://mobiusmdm.com/docs/configuration/mobius-server-configuration#redis) documentation.

## Systemd

### Run with systemd

Once you've verified that you can run Mobius in your shell, you'll likely want to keep Mobius running in the background and after the server reboots. To do that we recommend using [systemd](https://coreos.com/os/docs/latest/getting-started-with-systemd.html).

Below is a sample unit file, assuming a `mobius` user exists on the system. Any user with sufficient
permissions to execute the binary, open the configuration files, and write the log files can be
used. It is also possible to run as `root`, though as with any other web server it is discouraged
to run Mobius as `root`.

```systemd

[Unit]
Description=Mobius
After=network.target

[Service]
User=mobius
Group=mobius
LimitNOFILE=8192
ExecStart=/usr/local/bin/mobius serve \
  --mysql_address=127.0.0.1:3306 \
  --mysql_database=mobius \
  --mysql_username=root \
  --mysql_password=toor \
  --redis_address=127.0.0.1:6379 \
  --server_cert=/tmp/server.cert \
  --server_key=/tmp/server.key \
  --logging_json

[Install]
WantedBy=multi-user.target
```

Once you created the file, you need to move it to `/etc/systemd/system/mobius.service` and start the service.

```sh
sudo mv mobius.service /etc/systemd/system/mobius.service
sudo systemctl start mobius.service
sudo systemctl status mobius.service

sudo journalctl -u mobius.service -f
```

### Making changes

Sometimes you'll need to update the systemd unit file defining the service. To do that, first open /etc/systemd/system/mobius.service in a text editor, and make your modifications.

Then, run

```sh
sudo systemctl daemon-reload
sudo systemctl restart mobius.service
```

## TLS certificate

In order for osqueryd clients to connect, the connection to Mobius must use TLS. The TLS connection may be terminated by Mobius itself, or by a proxy serving traffic to Mobius.

- The CNAME or one of the Subject Alternate Names (SANs) on the certificate must match the hostname that osquery clients use to connect to the server/proxy.
- If you intend to have your Mobius instance on a subdomain, your certificate can have a wildcard SAN. So `mobius.example.com` should match a SAN of `*.example.com`
- If self-signed certificates are used, the full certificate chain must be provided to osquery via the `--tls_server_certs` flag.
- If Mobius terminates TLS, consider using an ECDSA (rather than RSA) certificate, as RSA certificates have been associated with [performance problems in Mobius due to Go's standard library TLS implementation](https://github.com/notawar/mobius/issues/655).

## Using a proxy

In enterprise environments where Mobius operates behind a proxy, you may need to configure proxy settings to enable services requiring outbound traffic, such as [vulnerability processing](https://mobiusmdm.com/docs/using-mobius/vulnerability-processing#vulnerability-processing) or [device management](https://mobiusmdm.com/device-management). Mobius automatically uses the `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` environment variables.

For example, to configure the proxy in a systemd service file:

```systemd
[Service]
Environment="HTTP_PROXY=http(s)://PROXY_URL:PORT/"
Environment="HTTPS_PROXY=http(s)://PROXY_URL:PORT/"
Environment="NO_PROXY=localhost,127.0.0.1,::1"
```

## Public IPs of devices

Mobius attempts to deduce the public IP of devices from well-known HTTP headers received on requests made by Mobius's agent (mobiusdaemon).

The HTTP request headers are checked in the following order:

1. If `True-Client-IP` header is set, then Mobius will extract its value.
2. If `X-Real-IP` header is set, then Mobius will extract its value.
3. If `X-Forwarded-For` header is set, then Mobius will extract the first comma-separated value.
4. If none of the above headers are present in the HTTP request then Mobius will attempt to use the remote address of the TCP connection (note that on deployments with ingress proxies the remote address seen by Mobius is the IP of the ingress proxy).

## Reference configuration strategies

You can easily run Mobius on a single VPS that would be capable of supporting hundreds if not thousands of hosts, but
this page details an [opinionated view](https://github.com/notawar/mobius/tree/main/infrastructure/dogfood/terraform/aws-tf-module) of running Mobius in a production environment, as
well as different configuration strategies to enable High Availability (HA).

### Availability components

There are a few strategies that can be used to ensure high availability:

- Database HA
- Traffic load balancing

#### Database HA

Mobius recommends RDS Aurora MySQL when running on AWS with [backups](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/Aurora.Managing.Backups.html) turned on. It is also
possible to dynamically scale read replicas to increase performance and [enable database fail-over](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/Concepts.AuroraHighAvailability.html).
It is also possible to use [Aurora Global](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/aurora-global-database.html) to
span multiple regions for more advanced configurations (_not included in the [reference terraform](https://github.com/notawar/mobius/tree/main/infrastructure/dogfood/terraform/aws-tf-module)_).

In some cases adding a read replica can increase database performance for specific access patterns. In scenarios when automating the API or with `mobiuscli`, there can be benefits to read performance.

**Note:Mobius servers need to talk to a writer in the same datacenter. Cross region replication can be used for failover but writes need to be local.**

#### Traffic load balancing

Load balancing enables distributing request traffic over many instances of the backend application. Using [AWS Application
Load Balancer](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/introduction.html) can also [offload SSL termination](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html), freeing Mobius to spend the majority of its allocated compute dedicated
to its core functionality.

_**Note if using [terraform reference architecture](https://github.com/notawar/mobius/tree/main/infrastructure/dogfood/terraform/aws-tf-module) all configurations can dynamically scale based on load(cpu/memory) and all configurations
assume On-Demand pricing (savings are available through Reserved Instances). Calculations do not take into account NAT gateway charges or other networking related ingress/egress costs.**_

### Cloud providers

#### Render

(Or any other PaaS)

###### Up to 300 hosts

See <https://mobiusmdm.com/docs/deploy/deploy-mobius#render>

#### AWS

##### Example configuration breakpoints

###### [Up to 1000 hosts](https://calculator.aws/#/estimate?id=7a821fc049a0ecc6ead22b6720246e55498be50e)

| Mobius instances | CPU Units     | RAM |
| --------------- | ------------- | --- |
| 1 Fargate task  | 512 CPU Units | 4GB |

| Dependencies | Version                 | Instance type   | Nodes |
| ------------ | ----------------------- | --------------- | ----- |
| Redis        | 6                       | cache.t4g.small | 3     |
| MySQL        | 8.0.mysql_aurora.3.07.1 | db.t4g.medium   | 2     |

###### [Up to 25000 hosts](https://calculator.aws/#/estimate?id=d735758715f059118dbce8dc42f3ff2410adc621)

| Mobius instances | CPU Units      | RAM |
| --------------- | -------------- | --- |
| 10 Fargate task | 1024 CPU Units | 4GB |

| Dependencies | Version                 | Instance type   | Nodes |
| ------------ | ----------------------- | --------------- | ----- |
| Redis        | 6                       | cache.m6g.large | 3     |
| MySQL        | 8.0.mysql_aurora.3.07.1 | db.r6g.large    | 2     |

###### [Up to 150000 hosts](https://calculator.aws/#/estimate?id=689fea65efff361ee070b15044a01224b8d26621)

| Mobius instances | CPU Units      | RAM |
| --------------- | -------------- | --- |
| 20 Fargate task | 1024 CPU Units | 4GB |

| Dependencies | Version                 | Instance type   | Nodes |
| ------------ | ----------------------- | --------------- | ----- |
| Redis        | 6                       | cache.m6g.large | 3     |
| MySQL        | 8.0.mysql_aurora.3.07.1 | db.r6g.4xlarge  | 2     |

###### [Up to 300000 hosts](https://calculator.aws/#/estimate?id=19b667fde567df0d64d9fae632d4885d7fdc726a)

| Mobius instances | CPU Units      | RAM |
| --------------- | -------------- | --- |
| 20 Fargate task | 1024 CPU Units | 4GB |

| Dependencies | Version                 | Instance type   | Nodes |
| ------------ | ----------------------- | --------------- | ----- |
| Redis        | 6                       | cache.m6g.large | 3     |
| MySQL        | 8.0.mysql_aurora.3.07.1 | db.r6g.16xlarge | 2     |

AWS reference architecture can be found in the [reference terraform](https://github.com/notawar/mobius-terraform/tree/main/example). This configuration includes:

- VPC
  - Subnets
    - Public & Private
  - ACLs
  - Security Groups
- ECS as the container orchestrator
  - Fargate for underlying compute
  - Task roles via IAM
- RDS Aurora MySQL 8
- Elasticache Redis Engine
- Firehose osquery log destination
  - S3 bucket sync to allow further ingestion/processing
- Carves/software stored in an S3 bucket

Additional addons are available such as:

- [Monitoring via Cloudwatch alarms](https://github.com/notawar/mobius-terraform/tree/main/addons/monitoring)

Some AWS services used in the provider reference architecture are billed as pay-per-use such as Firehose. This means that osquery scheduled query frequency can have
a direct correlation to how much these services cost, something to keep in mind when configuring Mobius in AWS.

###### AWS Terraform CI/CD IAM permissions

The following permissions are the minimum required to apply AWS terraform resources:

```JSON
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:*",
                "cloudwatch:*",
                "s3:*",
                "lambda:*",
                "ecs:*",
                "rds:*",
                "rds-data:*",
                "secretsmanager:*",
                "pi:*",
                "ecr:*",
                "iam:*",
                "aps:*",
                "vpc:*",
                "kms:*",
                "elasticloadbalancing:*",
                "ce:*",
                "cur:*",
                "logs:*",
                "cloudformation:*",
                "ssm:*",
                "sns:*",
                "elasticache:*",
                "application-autoscaling:*",
                "acm:*",
                "route53:*",
                "dynamodb:*",
                "kinesis:*",
                "firehose:*"
            ],
            "Resource": "*"
        }
    ]
}
```

#### GCP

GCP reference architecture can be found in [the Mobius repository](https://github.com/notawar/mobius/tree/main/infrastructure/dogfood/terraform/gcp). This configuration includes:

- Cloud Run (Mobius backend)
- Cloud SQL MySQL 8.0 (Mobius database)
- Memorystore Redis (Mobius cache & live query orchestrator)

GCP support for add/install software and file carve features is coming soon. Get [commmunity support](https://chat.osquery.io/c/mobius).

##### Example configuration breakpoints

###### [Up to 1000 hosts](https://cloud.google.com/products/calculator/#id=59670518-9af4-4044-af4a-cc100a9bed2f)

| Mobius instances | CPU | RAM |
| --------------- | --- | --- |
| 2 Cloud Run     | 1   | 2GB |

| Dependencies | Version               | Instance type |
| ------------ | --------------------- | ------------- |
| Redis        | MemoryStore Redis 6   | M1 Basic      |
| MySQL        | Cloud SQL for MySQL 8 | db-standard-1 |

###### [Up to 25000 hosts](https://cloud.google.com/products/calculator/#id=fadbb96c-967c-4397-9921-743d75b98d42)

| Mobius instances | CPU | RAM |
| --------------- | --- | --- |
| 10 Cloud Run    | 1   | 2GB |

| Dependencies | Version               | Instance type |
| ------------ | --------------------- | ------------- |
| Redis        | MemoryStore Redis 6   | M1 2GB        |
| MySQL        | Cloud SQL for MySQL 8 | db-standard-4 |

###### [Up to 150000 hosts](https://cloud.google.com/products/calculator/#id=baff774c-d294-491f-a9da-dd97bbfa8ef2)

| Mobius instances | CPU   | RAM |
| --------------- | ----- | --- |
| 30 Cloud Run    | 1 CPU | 2GB |

| Dependencies | Version               | Instance type | Nodes |
| ------------ | --------------------- | ------------- | ----- |
| Redis        | MemoryStore Redis 6   | M1 4GB        | 1     |
| MySQL        | Cloud SQL for MySQL 8 | db-highmem-16 | 1     |

#### Azure

Coming soon. Get [commmunity support](https://chat.osquery.io/c/mobius).

#### Render

Using [Render's IAC](https://render.com/docs/infrastructure-as-code) see [the repository](https://github.com/edwardsb/mobius-on-render) for full details.

```yaml
services:
  - name: mobius
    plan: standard
    type: web
    env: docker
    healthCheckPath: /healthz
    envVars:
      - key: MOBIUS_MYSQL_ADDRESS
        fromService:
          name: mobius-mysql
          type: pserv
          property: hostport
      - key: MOBIUS_MYSQL_DATABASE
        fromService:
          name: mobius-mysql
          type: pserv
          envVarKey: MYSQL_DATABASE
      - key: MOBIUS_MYSQL_PASSWORD
        fromService:
          name: mobius-mysql
          type: pserv
          envVarKey: MYSQL_PASSWORD
      - key: MOBIUS_MYSQL_USERNAME
        fromService:
          name: mobius-mysql
          type: pserv
          envVarKey: MYSQL_USER
      - key: MOBIUS_REDIS_ADDRESS
        fromService:
          name: mobius-redis
          type: pserv
          property: hostport
      - key: MOBIUS_SERVER_TLS
        value: false
      - key: PORT
        value: 8080

  - name: mobius-mysql
    type: pserv
    env: docker
    repo: https://github.com/render-examples/mysql
    branch: mysql-5
    disk:
      name: mysql
      mountPath: /var/lib/mysql
      sizeGB: 10
    envVars:
      - key: MYSQL_DATABASE
        value: mobius
      - key: MYSQL_PASSWORD
        generateValue: true
      - key: MYSQL_ROOT_PASSWORD
        generateValue: true
      - key: MYSQL_USER
        value: mobius

  - name: mobius-redis
    type: pserv
    env: docker
    repo: https://github.com/render-examples/redis
    disk:
      name: redis
      mountPath: /var/lib/redis
      sizeGB: 10
```

##### Digital Ocean

Using Digital Ocean's [App Spec](https://docs.digitalocean.com/products/app-platform/concepts/app-spec/) to deploy on the App on the [App Platform](https://docs.digitalocean.com/products/app-platform/)

```yaml
alerts:
- rule: DEPLOYMENT_FAILED
- rule: DOMAIN_FAILED
databases:
- cluster_name: mobius-redis
  engine: REDIS
  name: mobius-redis
  production: true
  version: "6"
- cluster_name: mobius-mysql
  db_name: mobius
  db_user: mobius
  engine: MYSQL
  name: mobius-mysql
  production: true
  version: "8"
domains:
- domain: demo.mobiusmdm.com
  type: PRIMARY
envs:
- key: MOBIUS_MYSQL_ADDRESS
  scope: RUN_TIME
  value: ${mobius-mysql.HOSTNAME}:${mobius-mysql.PORT}
- key: MOBIUS_MYSQL_PASSWORD
  scope: RUN_TIME
  value: ${mobius-mysql.PASSWORD}
- key: MOBIUS_MYSQL_USERNAME
  scope: RUN_TIME
  value: ${mobius-mysql.USERNAME}
- key: MOBIUS_MYSQL_DATABASE
  scope: RUN_TIME
  value: ${mobius-mysql.DATABASE}
- key: MOBIUS_REDIS_ADDRESS
  scope: RUN_TIME
  value: ${mobius-redis.HOSTNAME}:${mobius-redis.PORT}
- key: MOBIUS_SERVER_TLS
  scope: RUN_AND_BUILD_TIME
  value: "false"
- key: MOBIUS_REDIS_PASSWORD
  scope: RUN_AND_BUILD_TIME
  value: ${mobius-redis.PASSWORD}
- key: MOBIUS_REDIS_USE_TLS
  scope: RUN_AND_BUILD_TIME
  value: "true"
jobs:
- envs:
  - key: DATABASE_URL
    scope: RUN_TIME
    value: ${mobius-redis.DATABASE_URL}
  image:
    registry: mobiusmdm
    registry_type: DOCKER_HUB
    repository: mobius
    tag: latest
  instance_count: 1
  instance_size_slug: basic-xs
  kind: PRE_DEPLOY
  name: mobius-migrate
  run_command: mobius prepare --no-prompt=true db
  source_dir: /
name: mobius
region: nyc
services:
- envs:
  - key: MOBIUS_VULNERABILITIES_DATABASES_PATH
    scope: RUN_TIME
    value: /home/mobius
  health_check:
    http_path: /healthz
  http_port: 8080
  image:
    registry: mobiusmdm
    registry_type: DOCKER_HUB
    repository: mobius
    tag: latest
  instance_count: 1
  instance_size_slug: basic-xs
  name: mobius
  routes:
  - path: /
  run_command: mobius serve
  source_dir: /
```

## Monitoring Mobius

### Health checks

Mobius exposes a basic health check at the `/healthz` endpoint. This is the interface to use for simple monitoring and load-balancer health checks.

The `/healthz` endpoint will return an `HTTP 200` status if the server is running and has healthy connections to MySQL and Redis. If there are any problems, the endpoint will return an `HTTP 500` status. Details about failing checks are logged in the Mobius server logs.

Individual checks can be run by providing the `check` URL parameter (e.x., `/healthz?check=mysql` or `/healthz?check=redis`).

### Metrics

Mobius exposes server metrics in a format compatible with [Prometheus](https://prometheus.io/). A simple example Prometheus configuration is available in [tools/app/prometheus.yml](https://github.com/notawar/mobius/blob/194ad5963b0d55bdf976aa93f3de6cabd590c97a/tools/app/prometheus.yml).

Prometheus can be configured to use a wide range of service discovery mechanisms within AWS, GCP, Azure, Kubernetes, and more. See the Prometheus [configuration documentation](https://prometheus.io/docs/prometheus/latest/configuration/configuration/) for more information.

#### Alerting

##### Prometheus

Prometheus has built-in support for alerting through [Alertmanager](https://prometheus.io/docs/alerting/latest/overview/).

Consider building alerts for

- Changes from expected levels of host enrollment
- Increased latency on HTTP endpoints
- Increased error levels on HTTP endpoints

```
TODO (Seeking Contributors)
Add example alerting configurations
```

##### Cloudwatch Alarms

Cloudwatch Alarms can be configured to support a wide variety of metrics and anomaly detection mechanisms. There are some example alarms
in the terraform reference architecture (see `monitoring.tf`).

- [Monitoring RDS (MySQL)](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/monitoring-cloudwatch.html)
- [ElastiCache for Redis](https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/CacheMetrics.WhichShouldIMonitor.html)
- [Monitoring ECS](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/cloudwatch-metrics.html)
- Reference alarms include evaluating healthy targets & response times. We also use target-tracking alarms to manage auto-scaling.

#### Graphing

Prometheus provides basic graphing capabilities, and integrates tightly with [Grafana](https://prometheus.io/docs/visualization/grafana/) for sophisticated visualizations.

### Mobius server performance

Mobius is designed to scale to hundreds of thousands of online hosts. The Mobius server scales horizontally to support higher load.

#### Horizontal scaling

Scaling Mobius horizontally is as simple as running more Mobius server processes connected to the same MySQL and Redis backing stores. Typically, operators front Mobius server nodes with a load balancer that will distribute requests to the servers. All APIs in Mobius are designed to work in this arrangement by simply configuring clients to connect to the load balancer.

#### Availability

The Mobius/osquery system is resilient to loss of availability. Osquery agents will continue executing the existing configuration and buffering result logs during downtime due to lack of network connectivity, server maintenance, or any other reason. Buffering in osquery can be configured with the `--buffered_log_max` flag.

Note that short downtimes are expected during [Mobius server upgrades](https://mobiusmdm.com/docs/deploying/upgrading-mobius) that require database migrations.

#### Debugging performance issues

##### MySQL and Redis

If performance issues are encountered with the MySQL and Redis servers, use the extensive resources available online to optimize and understand these problems. Please [file an issue](https://github.com/notawar/mobius/issues/new/choose) with details about the problem so that Mobius developers can work to fix them.

##### Mobius server

For performance issues in the Mobius server process, please [file an issue](https://github.com/notawar/mobius/issues/new/choose) with details about the scenario, and attach a debug archive. Debug archives can also be submitted confidentially through other support channels.

###### Generate debug archive (Mobius 3.4.0+)

Use the `mobiuscli debug archive` command to generate an archive of Mobius's full suite of debug profiles. See the [mobiuscli setup guide](https://mobiusmdm.com/docs/using-mobius/mobiuscli-cli) for details on configuring `mobiuscli`.

The generated `.tar.gz` archive will be available in the current directory.

###### Targeting individual servers

In most configurations, the `mobiuscli` client is configured to make requests to a load balancer that will proxy the requests to each server instance. This can be problematic when trying to debug a performance issue on a specific server. To target an individual server, create a new `mobiuscli` context that uses the direct address of the server.

For example:

```sh
mobiuscli config set --context server-a --address https://server-a:8080
mobiuscli login --context server-a
mobiuscli debug archive --context server-a
```

###### Confidential information

The `mobiuscli debug archive` command retrieves information generated by Go's [`net/http/pprof`](https://golang.org/pkg/net/http/pprof/) package. In most scenarios this should not include sensitive information, however it does include command line arguments to the Mobius server. If the Mobius server receives sensitive credentials via CLI argument (not environment variables or config file), this information should be scrubbed from the archive in the `cmdline` file.

## Community projects

Below are some projects created by Mobius community members. These projects provide additional solutions for deploying Mobius. Please submit a pull request if you'd like your project featured.

- [CptOfEvilMinions/MobiusDM-Automation](https://github.com/CptOfEvilMinions/MobiusDM-Automation) - Ansible and Docker code to set up Mobius

<meta name="pageOrderInSection" value="400">
<meta name="description" value="An opinionated view of running Mobius in a production environment, and configuration strategies to enable high availability.">
