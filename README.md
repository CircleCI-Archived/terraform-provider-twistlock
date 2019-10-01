# Terraform Twistlock Provider

## Installing the plugin

```bash
make install
```

Call `terraform init` before running other Terraform commands in a directory
that contains Twistlock configuration. Terraform will tell you to do this if it
hasn't configured the Twistlock plugin before, or if you have upgraded the
plugin.

## Building the provider locally

```bash
make build
```

Make sure that `${GOPATH}/bin` is on your `${PATH}`, if not add it:

```bash
export PATH=${PATH}:${GOPATH}/bin
```

### Testing your local build with Terraform

```bash
make dev-install
```

And then run terraform command in your project.

## Creating release package

```bash
make release
```

Now we can create release package from local, and then upload to GitHub
release page manually

## Running tests

```bash
make test
```

## Running acceptance tests

Acceptance tests require a local running Twistlock Console.

Export env-vars to configure the provider

```bash
export HISTCONTROL=ignorespace

# leading space here can be used to ignore these commands stored in the shell
# command history when you set "HISTCONTROL=ignorespace" above
 export TWISTLOCK_USERNAME='user'
 export TWISTLOCK_PASSWORD='password'
 export TWISTLOCK_BASE_URL=http://localhost:8081/api/v1
```

Run tests with

```bash
make acceptance-test
```

### Re-generating keys for the User resource tests

User resources require PGP keys to generate passwords. The tests use known keys
to verify that the encrypted, generated password can be decrypted.

The secret key must have no passphrase in order to be usable during tests

Re-generate the keys in the `macOS`:

```bash
gpg --batch --gen-key gpg-key-generate.control
gpg --export terraform-provider-twistlock@acceptance.test | base64 --break=76 > twistlock/testdata/test-gpg-keys/terraform.pub
gpg --export-secret-keys terraform-provider-twistlock@acceptance.tes | base64 --break=76 > twistlock/testdata/test-gpg-keys/terraform.priv
gpg --delete-secret-and-public-key terraform-provider-twistlock@acceptance.test
```

## Sample terraform file

```terraform
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
# decrypt this since only Bob has the corresponding private key.
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


# `cve_policy` represents the CVE policy on a Twistlock Console. There can be
# only one CVE policy resource.
# The policy cannot be created or deleted, it can only be changed.
#
# If terraform is asked to delete the CVE policy resource it will instead
# delete all the rules from the policy.
resource "twistlock_cve_policy" "cve_policy" {
  rules = [{
     "owner" = "system"
     "name" = "Main catch-all CVE rule"
     "resources" {
       "hosts" = ["*"]
       "images" = ["*"]
       "labels" = ["*"]
       "containers" = ["*"]
     }
     "condition" = {
       "vulnerabilities" = [
         {"id" = 46, "block" = true, "minimum_severity" = 9}
       ]
       "cves" = {
         "ids" = ["CVE-2017-1234"]
         "effect" = "alert"
         "only_fixed" = true
       }
     }
     "block_message" = "This action has been blocked"
     "verbose" = "true"}
  ]
}
```
