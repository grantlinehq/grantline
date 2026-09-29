package platform

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/grantlinehq/grantline/internal/collectors/entra"
	gh "github.com/grantlinehq/grantline/internal/collectors/github"
	"github.com/grantlinehq/grantline/internal/collectors/jenkins"
	"github.com/grantlinehq/grantline/internal/collectors/kubernetes"
	"github.com/grantlinehq/grantline/internal/collectors/spire"
	"github.com/grantlinehq/grantline/internal/collectors/vault"
	"github.com/grantlinehq/grantline/internal/model"
	"io"
	kube "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

func (s *Server) collect(ctx context.Context, c Connection, credentials map[string]string) (model.Snapshot, error) {
	client, e := s.client()
	if e != nil {
		return model.Snapshot{}, e
	}
	source := c.Source
	token := credentials["token"]
	if source.Kind == "entra" && c.AuthMode == "client_secret" {
		token, e = entraAccessToken(ctx, client, source.TenantID, c.ClientID, credentials["client_secret"])
	}
	if source.Kind == "github" && c.AuthMode == "github_app" {
		token, e = githubAccessToken(ctx, client, c, credentials["private_key"])
	}
	if e != nil {
		return model.Snapshot{}, errors.New("provider authentication unavailable")
	}
	injected := func(name string) string {
		if name == "GRANTLINE_USERNAME" {
			return credentials["username"]
		}
		if name == "GRANTLINE_TOKEN" {
			return token
		}
		return ""
	}
	switch source.Kind {
	case "entra":
		return (entra.Collector{Config: source.EntraConfig(), Client: client, Credentials: injected}).Collect(ctx)
	case "github":
		return (gh.Collector{Config: source.GitHubConfig(), Client: client, Credentials: injected}).Collect(ctx)
	case "jenkins":
		cfg := source.JenkinsConfig()
		for i := range cfg.Jobs {
			for _, link := range c.Jenkinsfiles {
				if link.Job == cfg.Jobs[i].Path {
					cfg.Jobs[i].Jenkinsfile = &jenkins.Jenkinsfile{Repository: "github/" + link.GitHubSourceID + "/" + link.Repository, Commit: link.Commit, Path: link.Path}
				}
			}
		}
		return (jenkins.Collector{Config: cfg, Client: client, Credentials: injected, PinnedFile: func(ctx context.Context, file jenkins.Jenkinsfile) ([]byte, error) {
			for _, link := range c.Jenkinsfiles {
				if file.Repository == "github/"+link.GitHubSourceID+"/"+link.Repository && file.Commit == link.Commit && file.Path == link.Path {
					return s.githubJenkinsfile(ctx, client, link)
				}
			}
			return nil, errors.New("file mapping unavailable")
		}}).Collect(ctx)
	case "vault":
		roles := []vault.AuthRole{}
		for _, v := range source.AuthRoles {
			roles = append(roles, vault.AuthRole{Mount: v.Mount, Name: v.Name, Type: v.Type})
		}
		return (vault.Collector{Config: vault.Config{ID: source.ID, Address: source.Address, TokenEnv: source.TokenEnv, Scope: source.Scope, AuthRoles: roles, Policies: source.Policies}, Client: client, Credentials: injected}).Collect(ctx)
	case "kubernetes":
		raw, e := clientcmd.Load([]byte(credentials["kubeconfig"]))
		if e != nil {
			return model.Snapshot{}, errors.New("invalid kubeconfig")
		}
		// Kubeconfigs supplied over HTTP must never execute helpers or read server files.
		for _, a := range raw.AuthInfos {
			if a.Exec != nil || a.AuthProvider != nil || a.TokenFile != "" || a.ClientCertificate != "" || a.ClientKey != "" || a.Impersonate != "" || len(a.ImpersonateGroups) > 0 || len(a.ImpersonateUserExtra) > 0 {
				return model.Snapshot{}, errors.New("kubeconfig requires inline credentials without executable plugins or impersonation")
			}
		}
		for _, cluster := range raw.Clusters {
			u, e := url.Parse(cluster.Server)
			if e != nil || u.Scheme != "https" || u.User != nil || cluster.CertificateAuthority != "" || cluster.InsecureSkipTLSVerify || cluster.ProxyURL != "" {
				return model.Snapshot{}, errors.New("kubeconfig requires HTTPS and inline CA data")
			}
		}
		rest, e := clientcmd.NewNonInteractiveClientConfig(*raw, source.Context, &clientcmd.ConfigOverrides{}, nil).ClientConfig()
		if e != nil {
			return model.Snapshot{}, errors.New("kubeconfig context unavailable")
		}
		rest.Dial = s.dial
		rest.Timeout = 15 * time.Second
		rest.QPS = 10
		rest.Burst = 20
		k, e := kube.NewForConfig(rest)
		if e != nil {
			return model.Snapshot{}, errors.New("kubernetes client unavailable")
		}
		return (kubernetes.Collector{Client: k, Source: kubernetes.Source{ID: source.ID, KubeconfigPath: "managed", Context: source.Context, Scope: source.Scope}}).Collect(ctx)
	case "spire":
		value := credentials["export"]
		if len(value) == 0 || len(value) > spire.MaxExportBytes {
			return model.Snapshot{}, errors.New("bounded metadata export required")
		}
		f, e := os.CreateTemp("", "grantline-spire-*.json")
		if e != nil {
			return model.Snapshot{}, errors.New("temporary export unavailable")
		}
		defer os.Remove(f.Name())
		if _, e = f.WriteString(value); e != nil {
			f.Close()
			return model.Snapshot{}, e
		}
		if e = f.Close(); e != nil {
			return model.Snapshot{}, e
		}
		cfg := source.SpireConfig()
		cfg.ExportPath = f.Name()
		cfg.SocketPath = ""
		return (spire.Collector{Config: cfg}).Collect(ctx)
	}
	return model.Snapshot{}, errors.New("unsupported integration")
}
func entraAccessToken(ctx context.Context, client *http.Client, tenant, clientID, secret string) (string, error) {
	if !model.GitHubText(clientID, 128) || secret == "" {
		return "", errors.New("credentials missing")
	}
	form := url.Values{"client_id": {clientID}, "client_secret": {secret}, "grant_type": {"client_credentials"}, "scope": {"https://graph.microsoft.com/.default"}}
	req, e := http.NewRequestWithContext(ctx, "POST", "https://login.microsoftonline.com/"+url.PathEscape(tenant)+"/oauth2/v2.0/token", strings.NewReader(form.Encode()))
	if e != nil {
		return "", errors.New("authentication unavailable")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return exchangeToken(client, req, "access_token")
}
func githubAccessToken(ctx context.Context, client *http.Client, c Connection, keyPEM string) (string, error) {
	if !model.GitHubNumericID.MatchString(c.AppID) || !model.GitHubNumericID.MatchString(c.InstallationID) {
		return "", errors.New("numeric app and installation IDs required")
	}
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return "", errors.New("RSA key required")
	}
	key, e := x509.ParsePKCS1PrivateKey(block.Bytes)
	if e != nil {
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return "", errors.New("RSA key required")
		}
		var ok bool
		key, ok = parsed.(*rsa.PrivateKey)
		if !ok {
			return "", errors.New("RSA key required")
		}
	}
	if key.N.BitLen() < 2048 {
		return "", errors.New("RSA key too small")
	}
	now := time.Now().Unix()
	claims, _ := json.Marshal(map[string]any{"iat": now - 30, "exp": now + 300, "iss": c.AppID})
	unsigned := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." + base64.RawURLEncoding.EncodeToString(claims)
	sum := sha256.Sum256([]byte(unsigned))
	signature, e := rsa.SignPKCS1v15(nil, key, crypto.SHA256, sum[:])
	if e != nil {
		return "", errors.New("app assertion unavailable")
	}
	ids := []int64{}
	for _, repo := range c.Source.Repositories {
		id, e := strconv.ParseInt(repo.ID, 10, 64)
		if e != nil {
			return "", errors.New("invalid repository ID")
		}
		ids = append(ids, id)
	}
	payload, _ := json.Marshal(map[string]any{"permissions": map[string]string{"metadata": "read", "contents": "read", "actions": "read"}, "repository_ids": ids})
	req, e := http.NewRequestWithContext(ctx, "POST", "https://api.github.com/app/installations/"+c.InstallationID+"/access_tokens", bytes.NewReader(payload))
	if e != nil {
		return "", e
	}
	req.Header.Set("Authorization", "Bearer "+unsigned+"."+base64.RawURLEncoding.EncodeToString(signature))
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", gh.APIVersion)
	req.Header.Set("Content-Type", "application/json")
	return exchangeToken(client, req, "token")
}
func exchangeToken(client *http.Client, req *http.Request, key string) (string, error) {
	response, e := client.Do(req)
	if e != nil {
		return "", errors.New("authentication unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", errors.New("authentication rejected")
	}
	b, e := io.ReadAll(io.LimitReader(response.Body, 65537))
	if e != nil || len(b) > 65536 {
		return "", errors.New("invalid authentication response")
	}
	var body map[string]json.RawMessage
	var token string
	if json.Unmarshal(b, &body) != nil || json.Unmarshal(body[key], &token) != nil || token == "" || len(token) > 32768 || strings.ContainsAny(token, " \r\n\t") {
		return "", errors.New("invalid authentication response")
	}
	return token, nil
}
