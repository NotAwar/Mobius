variable "region" {
  description = "gcp region"
  default     = "us-central1"
}

variable "db_zone" {
  default = "us-central1-c"
}

variable "db_user" {
  default = "default"
}

variable "db_name" {
  default = "mobius"
}

variable "db_tier" {
  default = "db-custom-1-3840"
}

variable "db_version" {
  default = "MYSQL_8_0"
}

variable "mobius_cpu" {
  default = "1000m"
}

variable "mobius_memory" {
  default = "1024Mi"
}

variable "dns_zone" {
  default = ""
}

variable "dns_name" {
  default = ""
}

variable "serverless_connector_min_instances" {
  default = 2
}
variable "serverless_connector_max_instances" {
  default = 3
}

variable "serverless_connector_instance_type" {
  default = "f1-micro"
}

variable "vpc_subnet" {
  default = "10.10.10.0/28"
}

variable "project_id" {
  description = "gcp project id"
}

variable "prefix" {
  default     = "mobius"
  description = "prefix resources with this string"
}

variable "redis_mem" {
  default = 1
}

variable "image" {
  default = "mobiusmdm/mobius:v4.69.0"

variable "software_installers_bucket_name" {
  default = "mobius-software-installers"
}

variable "license_key" {
  default = ""
  description = "Mobius license key"
}

variable "debug_logging" {
  default = "false"
}
