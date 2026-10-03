package secrets

import (
	"context"
	"errors"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
)

// AzureKeyVault reads secrets from one Azure Key Vault.
type AzureKeyVault struct {
	client *azsecrets.Client
}

// NewAzureKeyVault returns a provider for the vault at vaultURI.
func NewAzureKeyVault(vaultURI string, cred azcore.TokenCredential) (*AzureKeyVault, error) {
	client, err := azsecrets.NewClient(vaultURI, cred, nil)
	if err != nil {
		return nil, err
	}
	return &AzureKeyVault{client: client}, nil
}

// Fetch returns the named secret; an empty version means the latest.
func (a *AzureKeyVault) Fetch(ctx context.Context, name, version string) (string, error) {
	resp, err := a.client.GetSecret(ctx, name, version, nil)
	if err != nil {
		return "", err
	}
	if resp.Value == nil {
		return "", errors.New("key vault returned no value")
	}
	return *resp.Value, nil
}
