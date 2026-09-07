# Common development and verification tasks for the PingFederate XAA proof.
#
# Credentialed Terraform targets expect TF_VAR_admin_password to be supplied
# by the caller. No password is stored in this file or in a saved plan command.

.DEFAULT_GOAL := help

NODE ?= node
TERRAFORM ?= terraform
DOCKER_COMPOSE ?= docker compose
MAVEN ?= mvn
POWERSHELL ?= powershell

PF_INSTALL_DIR ?= C:/development/pingfed/pingfederate/12.3.3
TFVARS ?= .local/local.tfvars.json
TFPLAN ?= .local/xaa.tfplan

COMPOSE_FILES := -f docker-compose.yml -f docker-compose.xaa.yml

.PHONY: help build java-build maven-package node-test test check \
	terraform-init terraform-fmt terraform-validate terraform-test terraform-plan terraform-apply \
	fixture live-proof smoke docker-config docker-build docker-up docker-down docker-logs

help: ## Show available tasks
	@echo Available tasks:
	@echo   build             Build the plugin and run Java proof checks
	@echo   test              Run Node.js and Terraform tests
	@echo   check             Run build, tests and static checks
	@echo   terraform-plan    Create a reviewable Terraform plan
	@echo   terraform-apply   Apply the already reviewed Terraform plan
	@echo   fixture           Create the disposable local fixture
	@echo   live-proof        Run the live local token endpoint proof
	@echo   smoke             Run the configured real-subject smoke test
	@echo   docker-up         Start PF with the plugin overlay
	@echo   docker-down       Stop PF without removing volumes

build: java-build ## Build the plugin and run the Java proof suite

java-build: ## Compile and package the plugin with the PF 12.3.3 SDK
	$(POWERSHELL) -NoProfile -ExecutionPolicy Bypass -File generator/build.ps1 -PfInstallDir "$(PF_INSTALL_DIR)"

maven-package: ## Package only with Maven; does not run the standalone Java proof
	$(MAVEN) -o -f generator/pom.xml -Dmaven.repo.local="$(USERPROFILE)/.m2/repository" -Dpf.install.dir="$(PF_INSTALL_DIR)" package

node-test: ## Run Node.js unit and verifier tests
	$(POWERSHELL) -NoProfile -Command "& '$(NODE)' --test"

test: node-test terraform-test ## Run Node.js and Terraform tests

check: build test terraform-fmt terraform-validate docker-config ## Run local build and static checks

terraform-init: ## Initialize pinned Terraform providers
	$(TERRAFORM) -chdir=terraform init -input=false

terraform-fmt: ## Check Terraform formatting
	$(TERRAFORM) -chdir=terraform fmt -check -recursive

terraform-validate: terraform-init ## Validate Terraform configuration
	$(TERRAFORM) -chdir=terraform validate -no-color

terraform-test: terraform-init ## Run Terraform configuration tests with mocked providers
	$(TERRAFORM) -chdir=terraform test -no-color

terraform-plan: terraform-init ## Create a reviewable plan at TFPLAN
	$(TERRAFORM) -chdir=terraform plan -input=false -no-color -var-file=../$(TFVARS) -out=../$(TFPLAN)

terraform-apply: ## Apply the already reviewed plan at TFPLAN
	@if not exist "$(TFPLAN)" (echo Missing $(TFPLAN). Run make terraform-plan first. && exit /b 1)
	$(TERRAFORM) -chdir=terraform apply -input=false -no-color ../$(TFPLAN)

fixture: ## Create the disposable local subject key and Terraform inputs
	$(POWERSHELL) -NoProfile -Command "& '$(NODE)' 'scripts/create-local-fixture.mjs'"

live-proof: ## Exercise live local issuance and negative cases; JWT claims display by default
	$(POWERSHELL) -NoProfile -Command "& '$(NODE)' 'scripts/live-local-proof.mjs'"

smoke: ## Exercise a configured real subject token; JWT claims display by default
	$(POWERSHELL) -NoProfile -Command "& '$(NODE)' '--env-file=.env' 'scripts/smoke-id-jag.mjs'"

docker-config: ## Validate the base Compose file and optional plugin overlay
	$(DOCKER_COMPOSE) $(COMPOSE_FILES) config --quiet

docker-build: java-build docker-config ## Build the optional PF image configuration
	$(DOCKER_COMPOSE) $(COMPOSE_FILES) build

docker-up: docker-build ## Start PF with the built plugin overlay
	$(DOCKER_COMPOSE) $(COMPOSE_FILES) up -d

docker-down: ## Stop the local PF container without removing volumes
	$(DOCKER_COMPOSE) $(COMPOSE_FILES) down

docker-logs: ## Follow local PF container logs
	$(DOCKER_COMPOSE) $(COMPOSE_FILES) logs -f pingfederate
