package repository

import (
	"testing"

	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/require"
)

func TestResourceHTTPClientAuthenticationSupportsBearerToken(t *testing.T) {
	authentication := ResourceHTTPClientAuthentication.Elem.(*schema.Resource)
	bearerToken, ok := authentication.Schema["bearer_token"]

	require.True(t, ok, "bearer_token must be present")
	require.True(t, bearerToken.Sensitive)

	diagnostics := authentication.Schema["type"].ValidateDiagFunc("bearerToken", cty.Path{})
	require.False(t, diagnostics.HasError())
}
