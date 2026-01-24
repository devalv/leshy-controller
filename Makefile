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
	go test ./... -race

# cover:
# 	go test ./... -race -cover

build:
#	$(MAKE) fmt
	go env -w CGO_ENABLED=0
	go env -w GOOS=linux
	go env -w GOARCH=amd64
	go build -o controller-app ./cmd

run:
	go run ./cmd --config ./config.yml

.PHONY: setup fmt test build
