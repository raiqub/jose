.PHONY: all build test benchmark test-cover generate list-imports

all: test build
	
build:
	go build ./...

test:
	go test -v ./...
	test -z "`gofmt -s -l -w . | tee /dev/stderr`"
	test -z "`golint ./... | grep -v ffjson | tee /dev/stderr`"
	go vet ./...

benchmark:
	go test -bench . -benchmem -run=^a ./... | grep "Benchmark" > bench_result.txt

test-cover:
	go test -cover `go list ./... | grep -v /vendor/`

generate:
	go generate `go list ./...`

list-imports:
	go list -f {{.Imports}} ./...
