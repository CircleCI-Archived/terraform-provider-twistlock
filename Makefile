GOPACKAGES = "github.com/circleci/terraform-provider-twistlock/..."
NAME = "terraform-provider-twistlock"
VERSION = "v1.0.0"

OS_NAME := $(shell uname -s | tr A-Z a-z)

build:
	go build -o $(NAME)_$(VERSION)

test:
	go test -coverprofile=coverage.out -covermode=count -v $(GOPACKAGES)

acceptance-test:
	TF_ACC=true go test -coverprofile=coverage.out -covermode=count -v $(GOPACKAGES)

fmt:
	@echo gofmt
	@if gofmt -l $(shell find . -name '*.go' -not -path './vendor/*') | grep . ; then exit 1; fi

# NB: there is no need to run `go vet`, `go test` runs `vet` and fails
# accordingly
check: test fmt

release:
	rm -rf dist
	mkdir -p dist

	GOOS=linux GOARCH=amd64 go build -o $(NAME)_$(VERSION)
	tar czf dist/$(NAME)-$(VERSION)-linux-amd64.tar.gz $(NAME)_$(VERSION)
	rm $(NAME)_$(VERSION)

	GOOS=darwin GOARCH=amd64 go build -o $(NAME)_$(VERSION)
	tar czf dist/$(NAME)-$(VERSION)-darwin-amd64.tar.gz $(NAME)_$(VERSION)
	rm $(NAME)_$(VERSION)

install:
	mkdir -p ~/.terraform.d/plugins
	wget -c https://github.com/circleci/terraform-provider-twistlock/releases/download/$(VERSION)/$(NAME)-$(VERSION)-$(OS_NAME)-amd64.tar.gz -O - | tar -xz -C ~/.terraform.d/plugins

dev-install:
	mkdir -p ~/.terraform.d/plugins
	make build
	mv $(NAME)_$(VERSION) ~/.terraform.d/plugins
