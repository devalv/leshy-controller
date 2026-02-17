SWAG_VERSION ?= v1.16.4

setup:
	go install golang.org/x/tools/cmd/goimports@latest
	go install mvdan.cc/gofumpt@latest

fmt:
	go mod tidy
	gofmt -w -s ./cmd ./internal
	gofumpt -w ./cmd ./internal
	goimports -w ./cmd ./internal
	golangci-lint run --fix

test:
	docker run --rm \
		-v $(PWD):/app \
		-w /app \
		golang:1.25-alpine \
		sh -c "apk add --no-cache build-base && go mod download && go env -w CGO_ENABLED=1 && go test -race -timeout=5m -v ./..."

cover:
	docker run --rm \
		-v $(PWD):/app \
		-w /app \
		golang:1.25-alpine \
		sh -c "go mod download && go test -coverprofile=coverage.out ./... && go tool cover -func=coverage.out"

build:
	$(MAKE) fmt
	go env -w CGO_ENABLED=0
	go env -w GOOS=linux
	go env -w GOARCH=amd64
	go build -o controller-app ./cmd/controller

build-cbpf:
	./devops/build.sh

build-deb:
	@if [ -z "$(VERSION)" ]; then \
		echo "Usage: make build-deb VERSION=1.2.3"; \
		exit 1; \
	fi
	PACKAGE_VERSION="$(VERSION)" ./devops/build-deb.sh

run:
	go run ./cmd --config ./config.yml

clean:
	docker system prune -f

swagger:
	mkdir -p docs/api/swagger
	docker run --rm \
		--user $$(id -u):$$(id -g) \
		-v $(PWD):/app \
		-w /app \
		golang:1.25-alpine \
		sh -c "export GOCACHE=/tmp/go-build GOPATH=/tmp/go GOMODCACHE=/tmp/go/pkg/mod && go install github.com/swaggo/swag/cmd/swag@$(SWAG_VERSION) && /tmp/go/bin/swag init --generalInfo swagger_info.go --dir internal/interfaces/rest/v1,internal/contracts/rest/v1 --output docs/api/swagger --outputTypes json,yaml --parseInternal --generatedTime=false"

.PHONY: setup fmt test build cover github-build run clean swagger build-deb
