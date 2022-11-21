package internal

import (
	"fmt"
	"github.com/jessevdk/go-flags"
	"strings"
)

type Config struct {
	ClientID         string   `env:"CLIENT_ID" long:"client-id" description:"OAuth application client ID" required:"true"`
	ClientSecret     string   `env:"CLIENT_SECRET" long:"client-secret" description:"OAuth application client secret" required:"true"`
	UserCookieName   string   `env:"USER_COOKIE_NAME" value-name:"name" long:"user-cookie-name" description:"Name of the cookie to save the authenticated user information in" required:"true"`
	UserCookieDomain string   `env:"USER_COOKIE_DOMAIN" value-name:"domain" long:"user-cookie-domain" description:"Domain for the user cookie" required:"true"`
	Scopes           string   `env:"SCOPES" long:"scopes" description:"OAuth scopes to request from the user" required:"true" default:"https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email"`
	AuthServiceHost  string   `env:"AUTH_SERVICE_HOST" value-name:"host-name" long:"auth-service-host" description:"OAuth application host name (this service)" required:"true"`
	HashingSecret    string   `env:"HASHING_SECRET" long:"hashing-secret" description:"The secret used for hashing user information (for verification)" required:"true"`
	Domains          []string `env:"DOMAINS" env-delim:"," long:"domains" description:"Comma-separated list of domains that are allowed to receive authentication and to login" required:"true"`
}

func NewConfig(config *Config) error {
	_, err := flags.Parse(config)
	return err
}

func (c *Config) getCallbackURL() string {
	return fmt.Sprintf("https://%s/callback", c.AuthServiceHost)
}

func (c *Config) isAllowedDomain(domain string) bool {
	if strings.Contains(domain, ":") {
		parts := strings.Split(domain, ":")
		domain = parts[0]
	}
	domain = strings.ToLower(domain)
	for _, allowedDomain := range c.Domains {
		lcAllowedDomain := strings.ToLower(allowedDomain)
		if domain == lcAllowedDomain || strings.HasSuffix(domain, "."+lcAllowedDomain) {
			return true
		}
	}
	return false
}
