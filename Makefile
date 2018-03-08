GOPACKAGES = "github.com/circleci/terraform-provider-twistlock/..."

build:
	go build

test:
	go test -coverprofile=coverage.out -covermode=count -v $(GOPACKAGES)

acceptance-test:
	TF_ACC=true go test -coverprofile=coverage.out -covermode=count -v $(GOPACKAGES)

fmt:
	@echo gofmt
	@if gofmt -l $(shell find . -name '*.go') | grep . ; then exit 1; fi

# NB: there is no need to run `go vet`, `go test` runs `vet` and fails
# accordingly
check: test fmt

install:
	go install
	terraform init
