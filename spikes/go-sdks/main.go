// Spike: build one static binary with the Azure, AWS and GCP secret SDKs, a YAML
// config parser and an embedded UI, then check that each piece works offline.
//
// The default run never touches the network or reads cloud environment
// variables. "call" uses the default credential chains and real API calls.
package main

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"

	"cloud.google.com/go/auth/credentials"
	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	awscreds "github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"go.yaml.in/yaml/v3"
	"google.golang.org/api/option"
)

//go:embed ui
var uiFiles embed.FS

type Config struct {
	Listen string `yaml:"listen"`
	Rules  []struct {
		Host string `yaml:"host"`
	} `yaml:"rules"`
}

func main() {
	ctx := context.Background()
	call := len(os.Args) > 1 && os.Args[1] == "call"

	check("yaml", checkYAML())
	check("azure", checkAzure(ctx, call))
	check("aws", checkAWS(ctx, call))
	check("gcp", checkGCP(ctx, call))
	check("ui", checkUI())
}

func check(name string, err error) {
	if err != nil {
		fmt.Printf("%-6s FAIL %v\n", name, err)
		os.Exit(1)
	}
	fmt.Printf("%-6s ok\n", name)
}

func checkYAML() error {
	var cfg Config
	if err := yaml.Unmarshal([]byte("listen: 127.0.0.1:8899\nrules:\n  - host: api.github.com\n"), &cfg); err != nil {
		return err
	}
	if cfg.Rules[0].Host != "api.github.com" {
		return fmt.Errorf("unexpected config %+v", cfg)
	}
	return nil
}

func checkAzure(ctx context.Context, call bool) error {
	var cred azcore.TokenCredential
	var err error
	if call {
		cred, err = azidentity.NewDefaultAzureCredential(nil)
	} else {
		opts := &azidentity.ClientSecretCredentialOptions{}
		opts.Cloud = cloud.AzurePublic
		cred, err = azidentity.NewClientSecretCredential("tenant", "client", "secret", opts)
	}
	if err != nil {
		return err
	}
	client, err := azsecrets.NewClient("https://example.vault.azure.net", cred, nil)
	if err != nil || !call {
		return err
	}
	_, err = client.GetSecret(ctx, "example", "", nil)
	return err
}

func checkAWS(ctx context.Context, call bool) error {
	if !call {
		_ = secretsmanager.New(secretsmanager.Options{
			Region:      "eu-north-1",
			Credentials: awscreds.NewStaticCredentialsProvider("id", "secret", ""),
		})
		return nil
	}
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("eu-north-1"))
	if err != nil {
		return err
	}
	client := secretsmanager.NewFromConfig(cfg)
	_, err = client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String("example")})
	return err
}

func checkGCP(ctx context.Context, call bool) error {
	// Same offline credential parse that failed under .NET AOT.
	creds, err := credentials.NewCredentialsFromJSON(credentials.AuthorizedUser,
		[]byte(`{"type":"authorized_user","client_id":"id","client_secret":"secret","refresh_token":"token"}`),
		&credentials.DetectOptions{Scopes: []string{"https://www.googleapis.com/auth/cloud-platform"}})
	if err != nil {
		return err
	}
	client, err := secretmanager.NewClient(ctx, option.WithAuthCredentials(creds))
	if err != nil {
		return err
	}
	defer client.Close()
	if !call {
		return nil
	}
	_, err = client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: "projects/example/secrets/example/versions/latest",
	})
	return err
}

func checkUI() error {
	sub, err := fs.Sub(uiFiles, "ui")
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: http.FileServerFS(sub)}
	go srv.Serve(ln)
	defer srv.Close()

	resp, err := http.Get("http://" + ln.Addr().String() + "/")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}
