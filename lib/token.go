package lib

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/1password/onepassword-sdk-go"
	vault "github.com/hashicorp/vault/api"
)

var tokenSource = flag.String("token", "env", "Source of Cloudflare token: 'env', '1password', or 'vault'")

func GetCloudflareToken() (string, error) {
	switch *tokenSource {
	case "env":
		if token := os.Getenv("CLOUDFLARE_API_TOKEN"); token != "" {
			return token, nil
		}
	case "1password":
		return getTokenFrom1Password()
	case "vault":
		return getTokenFromHashicorpVault()
	default:
		return "", fmt.Errorf("invalid token source: %s", *tokenSource)
	}

	return "", fmt.Errorf("no Cloudflare token found in %s", *tokenSource)
}

func getTokenFrom1Password() (string, error) {
	onepasswordToken := os.Getenv("OP_SERVICE_ACCOUNT_TOKEN")

	client, err := onepassword.NewClient(context.TODO(),
		onepassword.WithServiceAccountToken(onepasswordToken),
		onepassword.WithIntegrationInfo("My 1Password Integration", "v1.0.0"),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create 1Password client: %w", err)
	}

	reference := os.Getenv("CF_1PASSWORD_ITEM")
	if reference == "" {
		// op://<vault-name>/<item-name>/[section-name/]<field-name>
		reference = "op://vault/item-name/password"
	}

	secret, err := client.Secrets.Resolve(context.Background(), reference)
	if err != nil {
		return "", fmt.Errorf("failed to get token from 1Password: %w", err)
	}

	return strings.TrimSpace(secret), nil
}

func getTokenFromHashicorpVault() (string, error) {
	config := vault.DefaultConfig()

	// Override vault address if specified
	if addr := os.Getenv("VAULT_ADDR"); addr != "" {
		config.Address = addr
	}

	client, err := vault.NewClient(config)
	if err != nil {
		return "", fmt.Errorf("failed to create Vault client: %w", err)
	}

	// Use token from VAULT_TOKEN env var or token file
	if token := os.Getenv("VAULT_TOKEN"); token != "" {
		client.SetToken(token)
	}

	path := os.Getenv("CLOUDFLARE_VAULT_PATH")
	if path == "" {
		return "", fmt.Errorf("CLOUDFLARE_VAULT_PATH environment variable is required")
	}

	key := os.Getenv("CLOUDFLARE_VAULT_KEY")
	if key == "" {
		key = "token" // default key name
	}

	secret, err := client.Logical().Read(path)
	if err != nil {
		return "", fmt.Errorf("failed to read from Vault: %w", err)
	}
	if secret == nil {
		return "", fmt.Errorf("no secret found at path: %s", path)
	}

	tokenInterface, ok := secret.Data[key]
	if !ok {
		return "", fmt.Errorf("no key '%s' in secret at path: %s", key, path)
	}

	token, ok := tokenInterface.(string)
	if !ok {
		return "", fmt.Errorf("value at '%s' is not a string", key)
	}

	return strings.TrimSpace(token), nil
}
