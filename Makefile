setup:
	go install golang.org/x/tools/cmd/goimports@latest
	go install mvdan.cc/gofumpt@latest

fmt:
	go mod tidy
	gofmt -w -s ./cmd ./internal
	gofumpt -w ./cmd ./internal
	goimports -w ./cmd ./internal
	golangci-lint run

test:
	go test ./... -race

# cover:
# 	go test ./... -race -cover

build:
	$(MAKE) fmt
	go build -o application ./cmd/app

run:
	go run ./cmd/app --config ./config.yml

.PHONY: setup fmt test build
