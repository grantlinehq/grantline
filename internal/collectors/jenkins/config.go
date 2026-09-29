package jenkins

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

const (
	MaxJobs             = 100
	MaxDepth            = 8
	MaxBuilds           = 20
	maxResponseBytes    = 1 << 20
	maxJenkinsfileBytes = 256 << 10
)

type Config struct {
	ID, Address, UsernameEnv, TokenEnv, Scope string
	BuildLimit                                int
	Jobs                                      []Job
}

type Job struct {
	Path        string       `json:"path"`
	Kind        string       `json:"kind"`
	Jenkinsfile *Jenkinsfile `json:"jenkinsfile,omitempty"`
}

// Jenkinsfile selects a blob from a local repository at an immutable commit.
// Associating this supplied file with a live job is an operator declaration.
type Jenkinsfile struct {
	Repository string `json:"repository"`
	Commit     string `json:"commit"`
	Path       string `json:"path"`
}

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
var revision = regexp.MustCompile(`^(?:[a-f0-9]{40}|[a-f0-9]{64})$`)
var pathSegment = regexp.MustCompile(`^[A-Za-z0-9_ .-]+$`)
var referenceID = regexp.MustCompile(`^[A-Za-z0-9_.:/-]{1,256}$`)

func (c Config) Validate() error {
	if c.ID == "" || !strings.HasPrefix(c.Scope, "jenkins/") || !envName.MatchString(c.UsernameEnv) || !envName.MatchString(c.TokenEnv) {
		return fmt.Errorf("Jenkins requires id, jenkins scope, username_env and token_env")
	}
	u, err := url.Parse(c.Address)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("Jenkins address must be an HTTP(S) URL without credentials, query or fragment")
	}
	if u.Scheme == "http" && u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" && u.Hostname() != "::1" {
		return fmt.Errorf("Jenkins HTTP is restricted to loopback labs")
	}
	if u.RawPath != "" || (strings.Trim(u.Path, "/") != "" && !validPath(strings.Trim(u.Path, "/"), MaxDepth)) {
		return fmt.Errorf("unsupported Jenkins context path")
	}
	if len(c.Jobs) == 0 || len(c.Jobs) > MaxJobs || c.BuildLimit < 0 || c.BuildLimit > MaxBuilds {
		return fmt.Errorf("Jenkins needs 1..100 explicit items and build_limit between 0 and 20 (0 defaults to 5)")
	}
	seen := map[string]bool{}
	for _, job := range c.Jobs {
		if !validPath(job.Path, MaxDepth) || (job.Kind != "job" && job.Kind != "folder") || seen[job.Path] {
			return fmt.Errorf("invalid or duplicate Jenkins item; use literal full paths up to 8 segments and kind job|folder")
		}
		seen[job.Path] = true
		if file := job.Jenkinsfile; file != nil {
			if job.Kind != "job" || file.Repository == "" || !revision.MatchString(file.Commit) || !validPath(file.Path, 32) {
				return fmt.Errorf("Jenkinsfile requires a local repository, full lowercase commit ID and relative literal file path on a job")
			}
		}
	}
	return nil
}

func validPath(path string, depth int) bool {
	if path == "" || len(path) > 1024 {
		return false
	}
	parts := strings.Split(path, "/")
	if len(parts) > depth {
		return false
	}
	for _, p := range parts {
		if p == "." || p == ".." || p != strings.TrimSpace(p) || !pathSegment.MatchString(p) {
			return false
		}
	}
	return true
}

func jobEndpoint(path string) string {
	var b strings.Builder
	for _, p := range strings.Split(path, "/") {
		b.WriteString("/job/")
		b.WriteString(url.PathEscape(p))
	}
	return b.String() + "/api/json"
}

// Reference identity is job-scoped: identical labels do not prove the same
// credential store, domain, value or runtime identity across jobs or folders.
func CredentialNativeID(jobPath, id string) string {
	return jobPath + "/credentials/" + url.PathEscape(id)
}
