# Terraform Twistlock Provider

## Building the provider
```bash
$ go install
$ terraform init
```

## Running acceptance tests
Acceptance tests require a local running Twistlock Console.

Export env-vars to configure the provider
```bash
$ export HISTCONTROL=ignorespace
$   export TWISTLOCK_USERNAME='user'
$   export TWISTLOCK_PASSWORD='password'
$   export TWISTLOCK_BASE_URL=http://localhost:8081/api/v1
```

Run tests with
```bash
$ TF_ACC=true go test -v twistlock/*.go
```


## Sample terraform file
```
provider "twistlock" {
  "username" = "gordon"
  "password" = "gordon"
  "base_url" = "http://localhost:8081/api/v1"
}

# Bob is a twistlock account for a human. Bob's public key is used to encrypt
# a generated password.
resource "twistlock_user" "bob" {
  "username" = "bob"
  "password_pgp_key" = "${file("/tmp/bob.pub")}"
  "role" = "admin"
  "auth_type" = "basic"
}

# Output Bob's encrypted password after running. Only Bob will be able to
# decrypt this.
output "password" {
  value = "${twistlock_user.bob.encrypted_password}"
}

variable "ci_user_password" {}

# `ci_user` is a machine user, it's password is set from the
# `ci_user_password` variable. This will be stored in Terraform state.
resource "twistlock_machine_user" "ci_user" {
  "username" = "ci_user"
  "password" = "${var.ci_user_password}"
  "role" = "ci"
  "auth_type" = "basic"
}
```
