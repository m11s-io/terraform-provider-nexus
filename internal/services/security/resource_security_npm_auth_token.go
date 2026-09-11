package security

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/datadrivers/terraform-provider-nexus/internal/schema/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

type NpmAuthTokenClientConfig struct {
	URL                   string
	Insecure              bool
	Timeout               int
	ClientCertificatePath string
	ClientKeyPath         string
	RootCAPath            string
}

type npmAuthTokenLoginRequest struct {
	Name     string `json:"name"`
	Password string `json:"password"`
	Email    string `json:"email"`
	Type     string `json:"type"`
}

type npmAuthTokenLoginResponse struct {
	Token string `json:"token"`
}

type npmAuthTokenWhoamiResponse struct {
	Username string `json:"username"`
}

var npmAuthTokenClient = &npmAuthTokenHTTPClient{
	config: NpmAuthTokenClientConfig{Timeout: 30},
	client: &http.Client{Timeout: 30 * time.Second},
}

type npmAuthTokenHTTPClient struct {
	config NpmAuthTokenClientConfig
	client *http.Client
}

func ConfigureNpmAuthTokenClient(config NpmAuthTokenClientConfig) {
	if config.Timeout == 0 {
		config.Timeout = 30
	}

	npmAuthTokenClient = &npmAuthTokenHTTPClient{
		config: config,
		client: newNpmAuthTokenHTTPClient(config),
	}
}

func ResourceSecurityNpmAuthToken() *schema.Resource {
	return &schema.Resource{
		Description: "Use this resource to mint or reuse an npm bearer token through a Nexus npm repository login endpoint.",

		Create: resourceSecurityNpmAuthTokenCreate,
		Read:   resourceSecurityNpmAuthTokenRead,
		Update: resourceSecurityNpmAuthTokenCreate,
		Delete: resourceSecurityNpmAuthTokenDelete,

		Schema: map[string]*schema.Schema{
			"id": common.ResourceID,
			"repository": {
				Description: "The npm repository used for the login-compatible token endpoint.",
				ForceNew:    true,
				Type:        schema.TypeString,
				Required:    true,
			},
			"username": {
				Description: "The existing Nexus username to associate with the npm token.",
				ForceNew:    true,
				Type:        schema.TypeString,
				Required:    true,
			},
			"password": {
				Description: "The password for the existing Nexus user.",
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
			},
			"email": {
				Description: "The npm login email address sent to the registry endpoint.",
				Type:        schema.TypeString,
				Required:    true,
			},
			"token": {
				Description: "The npm bearer token. Use this as _authToken in .npmrc.",
				Type:        schema.TypeString,
				Computed:    true,
				Sensitive:   true,
			},
			"verified_username": {
				Description: "The username returned by the repository's /-/whoami endpoint for this token.",
				Type:        schema.TypeString,
				Computed:    true,
			},
		},
	}
}

func resourceSecurityNpmAuthTokenCreate(d *schema.ResourceData, m interface{}) error {
	repository := d.Get("repository").(string)
	username := d.Get("username").(string)

	token, err := npmAuthTokenClient.create(repository, npmAuthTokenLoginRequest{
		Name:     username,
		Password: d.Get("password").(string),
		Email:    d.Get("email").(string),
		Type:     "user",
	})
	if err != nil {
		return err
	}

	d.SetId(fmt.Sprintf("%s/%s", repository, username))
	d.Set("token", token.Token)
	return resourceSecurityNpmAuthTokenRead(d, m)
}

func resourceSecurityNpmAuthTokenRead(d *schema.ResourceData, m interface{}) error {
	token := d.Get("token").(string)
	if token == "" {
		d.SetId("")
		return nil
	}

	whoami, err := npmAuthTokenClient.whoami(d.Get("repository").(string), token)
	if err != nil {
		d.SetId("")
		return nil
	}

	d.Set("verified_username", whoami.Username)
	return nil
}

func resourceSecurityNpmAuthTokenDelete(d *schema.ResourceData, m interface{}) error {
	d.SetId("")
	return nil
}

func newNpmAuthTokenHTTPClient(config NpmAuthTokenClientConfig) *http.Client {
	var caCertPool *x509.CertPool
	if config.RootCAPath != "" {
		if caCert, err := os.ReadFile(config.RootCAPath); err == nil {
			if caCertPool, err = x509.SystemCertPool(); err != nil {
				caCertPool = x509.NewCertPool()
			}
			caCertPool.AppendCertsFromPEM(caCert)
		}
	}

	var certificates []tls.Certificate
	if config.ClientCertificatePath != "" && config.ClientKeyPath != "" {
		if cert, err := tls.LoadX509KeyPair(config.ClientCertificatePath, config.ClientKeyPath); err == nil {
			certificates = []tls.Certificate{cert}
		}
	}

	return &http.Client{
		Timeout: time.Duration(config.Timeout) * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: config.Insecure,
				RootCAs:            caCertPool,
				Certificates:       certificates,
			},
		},
	}
}

func (c *npmAuthTokenHTTPClient) create(repository string, request npmAuthTokenLoginRequest) (*npmAuthTokenLoginResponse, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPut, c.url(repository, "-/user/org.couchdb.user:"+url.PathEscape(request.Name)), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	responseBody, statusCode, err := c.do(req)
	if err != nil {
		return nil, err
	}
	if statusCode != http.StatusOK && statusCode != http.StatusCreated {
		return nil, fmt.Errorf("could not create npm auth token: HTTP: %d, %v", statusCode, string(responseBody))
	}

	token := &npmAuthTokenLoginResponse{}
	if err := json.Unmarshal(responseBody, token); err != nil {
		return nil, fmt.Errorf("could not unmarshal npm auth token response: %v", err)
	}
	if token.Token == "" {
		return nil, fmt.Errorf("npm auth token response did not include a token")
	}

	return token, nil
}

func (c *npmAuthTokenHTTPClient) whoami(repository string, token string) (*npmAuthTokenWhoamiResponse, error) {
	req, err := http.NewRequest(http.MethodGet, c.url(repository, "-/whoami"), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	responseBody, statusCode, err := c.do(req)
	if err != nil {
		return nil, err
	}
	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("could not verify npm auth token: HTTP: %d, %v", statusCode, string(responseBody))
	}

	whoami := &npmAuthTokenWhoamiResponse{}
	if err := json.Unmarshal(responseBody, whoami); err != nil {
		return nil, fmt.Errorf("could not unmarshal npm whoami response: %v", err)
	}

	return whoami, nil
}

func (c *npmAuthTokenHTTPClient) do(req *http.Request) ([]byte, int, error) {
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	return body, resp.StatusCode, err
}

func (c *npmAuthTokenHTTPClient) url(repository string, path string) string {
	return fmt.Sprintf("%s/repository/%s/%s", strings.TrimRight(c.config.URL, "/"), url.PathEscape(repository), path)
}
