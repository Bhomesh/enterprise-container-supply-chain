.PHONY: help build-image scan test lint run-gatekeeper clean-registries

help:
	@echo "Enterprise Container Supply Chain Pipeline Commands:"
	@echo "  make build-image     - Build hardened multi-stage container image"
	@echo "  make scan            - Scan container image with Trivy and Syft"
	@echo "  make run-gatekeeper  - Evaluate vulnerability scan results against security gate"
	@echo "  make test            - Execute Python unit and integration test suite"
	@echo "  make start-registries- Spin up local Intake and Golden Docker registries"

build-image:
	docker build -f docker/Dockerfile.hardened -t intake.registry.corp/payments/core-api:1.0.0-rc1 .

scan:
	mkdir -p reports
	@which trivy >/dev/null 2>&1 && trivy image --format json --output reports/trivy-scan.json intake.registry.corp/payments/core-api:1.0.0-rc1 || echo "Trivy not installed, using mock fixtures"

run-gatekeeper:
	python3 src/gatekeeper.py --report tests/fixtures/trivy_sample_clean.json --waivers policies/cve_waivers.yaml --policy policies/security_gate_rules.yaml

test:
	python3 -m unittest discover -s tests -p "test_*.py"

start-registries:
	docker compose -f docker/docker-compose.yml up -d

clean-registries:
	docker compose -f docker/docker-compose.yml down -v
