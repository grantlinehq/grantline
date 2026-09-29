package platform

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	gh "github.com/grantlinehq/grantline/internal/collectors/github"
	"github.com/grantlinehq/grantline/internal/model"
)

type connectionSnapshotKey struct{}

func (s *Server) githubJenkinsfile(ctx context.Context, client *http.Client, link LinkedJenkinsfile) ([]byte, error) {
	var c Connection
	var credentials map[string]string
	if snapshot, ok := ctx.Value(connectionSnapshotKey{}).(map[string]runConnection); ok {
		record, exists := snapshot[link.GitHubSourceID]
		if !exists || record.Failure {
			return nil, errors.New("linked connection unavailable")
		}
		c, credentials = record.Config, record.Credentials
	} else {
		var enabled bool
		if s.db.QueryRowContext(ctx, "SELECT enabled FROM integrations WHERE id=$1", link.GitHubSourceID).Scan(&enabled) != nil || !enabled {
			return nil, errors.New("linked connection must be enabled")
		}
		var err error
		c, credentials, _, err = s.connection(ctx, link.GitHubSourceID)
		if err != nil {
			return nil, errors.New("linked connection unavailable")
		}
	}
	if c.Source.Kind != "github" {
		return nil, errors.New("GitHub connection required")
	}
	allowed := false
	for _, repo := range c.Source.Repositories {
		if repo.Name == link.Repository && repo.ID == link.RepositoryID {
			allowed = true
		}
	}
	if !allowed {
		return nil, errors.New("repository outside linked scope")
	}
	token := credentials["token"]
	if c.AuthMode == "github_app" {
		var err error
		token, err = githubAccessToken(ctx, client, c, credentials["private_key"])
		if err != nil {
			return nil, err
		}
	}
	get := func(path string, target any) error {
		req, e := http.NewRequestWithContext(ctx, "GET", gh.Address+path, nil)
		if e != nil {
			return errors.New("metadata unavailable")
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", gh.APIVersion)
		response, e := client.Do(req)
		if e != nil {
			return errors.New("metadata unavailable")
		}
		defer response.Body.Close()
		if response.StatusCode != 200 {
			return errors.New("metadata access failed")
		}
		b, e := io.ReadAll(io.LimitReader(response.Body, (512<<10)+1))
		if e != nil || len(b) > 512<<10 || json.Unmarshal(b, target) != nil {
			return errors.New("bounded metadata required")
		}
		return nil
	}
	var repository struct {
		ID       json.Number `json:"id"`
		FullName string      `json:"full_name"`
	}
	if get("/repos/"+link.Repository, &repository) != nil || repository.ID.String() != link.RepositoryID || !strings.EqualFold(repository.FullName, link.Repository) {
		return nil, errors.New("repository identity mismatch")
	}
	// An immutable commit must resolve before its file can be used as declared evidence.
	var commit struct {
		SHA    string `json:"sha"`
		Commit struct {
			Tree struct {
				SHA string `json:"sha"`
			} `json:"tree"`
		} `json:"commit"`
	}
	if get("/repos/"+link.Repository+"/commits/"+link.Commit, &commit) != nil || commit.SHA != link.Commit || !model.GitHubSHA.MatchString(commit.Commit.Tree.SHA) {
		return nil, errors.New("commit unavailable")
	}
	sha := commit.Commit.Tree.SHA
	parts := strings.Split(link.Path, "/")
	if len(parts) > 32 {
		return nil, errors.New("file path too deep")
	}
	for i, part := range parts {
		var tree struct {
			Truncated bool                                     `json:"truncated"`
			Tree      []struct{ Path, Mode, Type, SHA string } `json:"tree"`
		}
		if get("/repos/"+link.Repository+"/git/trees/"+sha, &tree) != nil || tree.Truncated {
			return nil, errors.New("tree metadata incomplete")
		}
		found := false
		for _, entry := range tree.Tree {
			if entry.Path != part {
				continue
			}
			if found || !model.GitHubSHA.MatchString(entry.SHA) {
				return nil, errors.New("ambiguous tree metadata")
			}
			found = true
			if i == len(parts)-1 {
				if entry.Type != "blob" || (entry.Mode != "100644" && entry.Mode != "100755") {
					return nil, errors.New("regular file required")
				}
			} else if entry.Type != "tree" || entry.Mode != "040000" {
				return nil, errors.New("directory required")
			}
			sha = entry.SHA
		}
		if !found {
			return nil, errors.New("pinned path unavailable")
		}
	}
	var file struct {
		SHA      string `json:"sha"`
		Encoding string `json:"encoding"`
		Content  string `json:"content"`
		Size     int    `json:"size"`
	}
	if get("/repos/"+link.Repository+"/git/blobs/"+sha, &file) != nil || file.SHA != sha || file.Encoding != "base64" || file.Size < 0 || file.Size > 256<<10 {
		return nil, errors.New("regular bounded Jenkinsfile required")
	}
	b, e := base64.StdEncoding.DecodeString(strings.ReplaceAll(file.Content, "\n", ""))
	if e != nil || len(b) != file.Size {
		return nil, errors.New("Jenkinsfile content invalid")
	}
	return b, nil
}
