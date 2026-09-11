# m11s changes to upstream

This repository tracks [datadrivers/terraform-provider-nexus](https://github.com/datadrivers/terraform-provider-nexus)
and publishes a small extension set as `m11s-io/nexus`.

Upstream base: **v3.0.1**

## npm proxy bearer-token authentication

Adds `bearerToken` as an HTTP client authentication type for npm proxy
repositories and exposes its sensitive `bearer_token` value.

This change has also been proposed upstream in
[datadrivers/terraform-provider-nexus#609](https://github.com/datadrivers/terraform-provider-nexus/pull/609).

## npm auth-token resource

Adds `nexus_security_npm_auth_token`, which authenticates an existing Nexus
user through an npm repository's registry-compatible login endpoint and stores
the resulting bearer token in Terraform state.

The Nexus `NpmToken` realm must be active. Nexus exposes no corresponding
public operation for revoking this npm bearer token, so destroying the resource
removes it from Terraform state but does not revoke it on the server.

