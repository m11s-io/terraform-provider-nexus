package security

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResourceSecurityNpmAuthTokenSchema(t *testing.T) {
	resource := ResourceSecurityNpmAuthToken()

	require.NotNil(t, resource.Create)
	require.NotNil(t, resource.Read)
	require.NotNil(t, resource.Update)
	require.NotNil(t, resource.Delete)
	require.True(t, resource.Schema["password"].Sensitive)
	require.True(t, resource.Schema["token"].Sensitive)
	require.True(t, resource.Schema["token"].Computed)
	require.True(t, resource.Schema["repository"].ForceNew)
	require.True(t, resource.Schema["username"].ForceNew)
}

func TestNpmAuthTokenClientCreateAndWhoami(t *testing.T) {
	var loginSeen bool
	var whoamiSeen bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repository/npm-internal/-/user/org.couchdb.user:ci-npm-publish":
			require.Equal(t, http.MethodPut, r.Method)

			var request npmAuthTokenLoginRequest
			require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
			require.Equal(t, "ci-npm-publish", request.Name)
			require.Equal(t, "test-password", request.Password)
			require.Equal(t, "ci@example.test", request.Email)
			require.Equal(t, "user", request.Type)

			loginSeen = true
			w.Header().Set("Content-Type", "application/json")
			require.NoError(t, json.NewEncoder(w).Encode(map[string]string{"token": "test-token"}))
		case "/repository/npm-internal/-/whoami":
			require.Equal(t, http.MethodGet, r.Method)
			require.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))

			whoamiSeen = true
			w.Header().Set("Content-Type", "application/json")
			require.NoError(t, json.NewEncoder(w).Encode(map[string]string{"username": "ci-npm-publish"}))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := &npmAuthTokenHTTPClient{
		config: NpmAuthTokenClientConfig{URL: server.URL, Timeout: 30},
		client: server.Client(),
	}

	token, err := client.create("npm-internal", npmAuthTokenLoginRequest{
		Name:     "ci-npm-publish",
		Password: "test-password",
		Email:    "ci@example.test",
		Type:     "user",
	})
	require.NoError(t, err)
	require.Equal(t, "test-token", token.Token)

	whoami, err := client.whoami("npm-internal", token.Token)
	require.NoError(t, err)
	require.Equal(t, "ci-npm-publish", whoami.Username)
	require.True(t, loginSeen)
	require.True(t, whoamiSeen)
}
