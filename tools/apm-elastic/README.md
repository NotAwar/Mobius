# Running a local Elastic/Kibana APM

## Setup

To setup a full Elastic APM stack, from this directory, run:

```
docker compose up -d
docker compose exec apm-server ./apm-server setup
```

Give it a few seconds to complete setup, and then you should be able to view the APM website at `http://localhost:5601`.

## Configuring local Mobius

Make sure Mobius is ready to run locally (docker services are started, binary is built, etc., see [Testing and local development](../../docs/Contributing/getting-started/testing-and-local-development.md)).

Start the locally-built Mobius (`mobius serve`) and provide the `--logging_tracing_enabled --logging_tracing_type=elasticapm` flags (note that sending those options using environment variables does not seem to work).

Navigate the Mobius website and you should start seeing API requests and (eventually) errors show up in the APM dashboard (<http://localhost:5601/app/apm>).

You may set the following environment variables to further configure the APM data collection:

```
ELASTIC_APM_SERVICE_NAME=mobius
ELASTIC_APM_ENVIRONMENT=development
ELASTIC_APM_TRANSACTION_SAMPLE_RATE=1
```

The default values should be fine for a local environment (in particular, the sample rate defaults to 1.0 so all events are recorded).
