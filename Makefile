.PHONY: all build test benchmark test-cover test-cover-html generate list-imports
PACKAGES = $(shell find ./ -type d -not -path '*/\.*')

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
	@go test -cover `go list ./... | grep -v /vendor/` | grep "%"
	
test-cover-html:
	echo "mode: count" > coverage-all.out
	$(foreach pkg,$(PACKAGES),\
		go test -coverprofile=coverage.out -covermode=count $(pkg);\
		tail -n +2 coverage.out >> coverage-all.out;)
	go tool cover -html=coverage-all.out
	rm -f coverage.out
	rm -f coverage-all.out

generate:
	go generate `go list ./...`

list-imports:
	go list -f {{.Imports}} ./...
