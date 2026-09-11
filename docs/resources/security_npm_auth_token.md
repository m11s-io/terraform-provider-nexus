---
page_title: "nexus_security_npm_auth_token Resource - nexus"
subcategory: "Security"
description: |-
  Mints or reuses an npm bearer token through a Nexus npm repository login endpoint.
---

# nexus_security_npm_auth_token (Resource)

Mints or reuses an npm bearer token for an existing Nexus user through the npm
registry-compatible login endpoint. The Nexus `NpmToken` realm must be active.

Both `password` and `token` are sensitive, but sensitive Terraform values are
still stored in state. Protect the state backend accordingly.

Nexus exposes no corresponding public operation for revoking this npm bearer
token. Destroying the resource removes it from Terraform state but does not
revoke it on the server.

## Example Usage

```terraform
resource "nexus_security_npm_auth_token" "ci" {
  repository = "npm-internal"
  username   = "ci-npm-publish"
  password   = var.ci_npm_publish_password
  email      = "ci-npm-publish@example.com"
}

output "npm_auth_token" {
  value     = nexus_security_npm_auth_token.ci.token
  sensitive = true
}
```

## Schema

### Required

- `repository` (String) Repository used for the npm login-compatible endpoint.
- `username` (String) Existing Nexus user associated with the token.
- `password` (String, Sensitive) Password for the existing Nexus user.
- `email` (String) Email sent to the npm login endpoint.

### Read-Only

- `id` (String)
- `token` (String, Sensitive) Generated npm bearer token.
- `verified_username` (String) Username returned by npm `whoami`.

