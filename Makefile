setup:
	go install golang.org/x/tools/cmd/goimports@latest
	go install mvdan.cc/gofumpt@latest

fmt:
	go mod tidy
	gofmt -w -s ./cmd ./internal
	gofumpt -w ./cmd ./internal
	goimports -w ./cmd ./internal
# 	golangci-lint run --fix

test:
	docker run --rm \
		-v $(PWD):/app \
		-w /app \
		golang:1.25-alpine \
		sh -c "go mod download && go test -v ./..."

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

run:
	go run ./cmd --config ./config.yml

clean:
	docker system prune -f

.PHONY: setup fmt test build
