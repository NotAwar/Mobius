#! /usr/bin/env make
#
# While not very elegant as far as Makefiles go, this Makefile does
# contain the basic commands to get you terraforming your MobiusDM
# teams. See the README for details.

provider_code_spec.json: openapi.json
	tfplugingen-openapi generate --config generator.yaml --output ./provider_code_spec.json ./openapi.json

provider/team_resource_gen.go: provider_code_spec.json
	tfplugingen-framework generate resources --input provider_code_spec.json --output ./provider --package provider

.PHONY: install build test tidy gen plan apply

gen: provider/team_resource_gen.go

install: gen
	go install ./...

build: gen
	go build ./...

test: gen
	@test -n "$(MOBIUSDAEMONM_APIKEY)" || (echo "MOBIUSDAEMONM_APIKEY is not set" && exit 1)
	MOBIUSDAEMONM_URL='https://rbx.cloud.mobiusmdm.com' TF_ACC=1 go test ./...

tidy:
	go mod tidy

plan: tf/terraformrc-dev-override
	cd tf && TF_CLI_CONFIG_FILE=./terraformrc-dev-override terraform plan

apply: tf/terraformrc-dev-override
	cd tf && TF_CLI_CONFIG_FILE=./terraformrc-dev-override terraform apply -auto-approve

tf/terraformrc-dev-override:
	@echo "provider_installation { \\n\
  dev_overrides { \\n\
    \"mobiusmdm.com/tf/mobiusmdm\" = \"$$HOME/go/bin\" \\n\
  } \\n\
  direct {} \\n\
}" > $@
