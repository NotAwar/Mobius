locals {
  name   = "mobiusmdm-${terraform.workspace}"
  prefix = "mobius-${terraform.workspace}"
  additional_env_vars = [for k, v in merge({
    "MOBIUS_VULNERABILITIES_DATABASES_PATH" : "/home/mobius"
    "MOBIUS_OSQUERY_ENABLE_ASYNC_HOST_PROCESSING" : "false"
    "MOBIUS_LOGGING_DEBUG" : "true"
    "MOBIUS_LOGGING_TRACING_ENABLED" : "true"
    "MOBIUS_LOGGING_TRACING_TYPE" : "elasticapm"
    "ELASTIC_APM_SERVER_URL" : "https://loadtest.mobiusmdm.com:8200"
    "ELASTIC_APM_SERVICE_NAME" : "mobius"
    "ELASTIC_APM_ENVIRONMENT" : "${terraform.workspace}"
    "ELASTIC_APM_TRANSACTION_SAMPLE_RATE" : "0.004"
    "ELASTIC_APM_SERVICE_VERSION" : "${var.tag}-${split(":", data.docker_registry_image.dockerhub.sha256_digest)[1]}"
  }, var.mobius_config) : { name = k, value = v }]
  # Private Subnets from VPN VPC
  vpn_cidr_blocks = [
    "10.255.1.0/24",
    "10.255.2.0/24",
    "10.255.3.0/24",
  ]

}
