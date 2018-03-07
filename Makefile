.PHONY: test

build:
	go build

test:
	go test -coverprofile=coverage.out -v github.com/circleci/terraform-provider-twistlock/...

acceptance-test:
	TF_ACC=true go test -coverprofile=coverage.out -v github.com/circleci/terraform-provider-twistlock/...

install:
	go install
	terraform init
