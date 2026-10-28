package oauth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"golang.org/x/oauth2"
)

func TestHandleAuthorizeRequestAudience(t *testing.T) {
	tests := []struct {
		name            string
		requestAudience bool
		audience        string
		wantAudience    string
	}{
		{
			name:            "audience requested",
			requestAudience: true,
			audience:        "https://mcp.example.com",
			wantAudience:    "https://mcp.example.com",
		},
		{
			name:            "audience not requested by default",
			requestAudience: false,
			audience:        "https://mcp.example.com",
		},
		{
			name:            "nothing to request without audience",
			requestAudience: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := &OAuth2Handler{
				config: &OAuth2Config{
					Mode:            "proxy",
					RedirectURIs:    "https://client.example.com/callback",
					Audience:        tt.audience,
					RequestAudience: tt.requestAudience,
				},
				oauth2Config: &oauth2.Config{
					ClientID: "test-client",
					Endpoint: oauth2.Endpoint{AuthURL: "https://idp.example.com/oauth2/auth"},
				},
				logger: &defaultLogger{},
			}

			req := httptest.NewRequest("GET", "/oauth/authorize?redirect_uri="+url.QueryEscape("https://client.example.com/callback")+"&state=abc", nil)
			rec := httptest.NewRecorder()
			handler.HandleAuthorize(rec, req)

			if rec.Code != http.StatusTemporaryRedirect {
				t.Fatalf("expected redirect, got %d: %s", rec.Code, rec.Body.String())
			}
			location, err := url.Parse(rec.Header().Get("Location"))
			if err != nil {
				t.Fatalf("invalid Location header: %v", err)
			}
			query := location.Query()
			if got := query.Get("audience"); got != tt.wantAudience {
				t.Errorf("audience = %q, want %q", got, tt.wantAudience)
			}
			if got := query.Get("access_type"); got != "offline" {
				t.Errorf("access_type = %q, want offline", got)
			}
		})
	}
}

func TestFromEnvJumpCloudOptions(t *testing.T) {
	t.Setenv("OAUTH_PROVIDER", "hmac")
	t.Setenv("OIDC_AUDIENCE", "test-audience")
	t.Setenv("JWT_SECRET", "test-secret")
	t.Setenv("OIDC_REQUEST_AUDIENCE", "true")
	t.Setenv("OIDC_REQUIRED_CLIENT_ID", "test-client")

	cfg, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv() error = %v", err)
	}
	if !cfg.RequestAudience {
		t.Error("RequestAudience = false, want true")
	}
	if cfg.RequiredClientID != "test-client" {
		t.Errorf("RequiredClientID = %q, want test-client", cfg.RequiredClientID)
	}
	if got := NewOAuth2ConfigFromConfig(cfg, "test").RequestAudience; !got {
		t.Error("OAuth2Config.RequestAudience = false, want true")
	}
}
