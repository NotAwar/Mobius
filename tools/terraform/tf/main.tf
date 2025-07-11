terraform {
  required_providers {
    mobiusmdm = {
      source = "mobiusmdm.com/tf/mobiusmdm"
    }
  }
}

provider "mobiusmdm" {
  url = "https://something.cloud.mobiusmdm.com"
  // apikey provided via MOBIUSDAEMONM_APIKEY
}

locals {
  # Here are some default agent options.
  default_agent_options = jsonencode(local.raw_agent_options)
  raw_agent_options = {
    "config" = {
      "options" = {
        pack_delimiter               = "/"
        logger_tls_period            = 10
        distributed_plugin           = "tls"
        disable_distributed          = false
        logger_tls_endpoint          = "/api/osquery/log"
        distributed_interval         = 15
        distributed_tls_max_attempts = 3
      }
      "decorators" = {
        "load" = [
          "SELECT uuid AS host_uuid FROM system_info;",
          "SELECT hostname AS hostname FROM system_info;"
        ]
      }
    }
    command_line_flags = {
      disable_events    = true
      enable_bpf_events = false
    }
  }
}

resource "mobiusdm_teams" "hello_world" {
  name          = "my_first_team"
  description   = "This is my first team"
  agent_options = local.default_agent_options
}
