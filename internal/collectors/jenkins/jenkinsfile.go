package jenkins

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

type Reference struct {
	ID   string
	Line int
}
type ParseResult struct {
	References []Reference
	Unresolved bool
}
type lexeme struct {
	text            string
	quoted, literal bool
	line            int
	interpolated    bool
}

// ParseJenkinsfile is a conservative lexer, not a Groovy interpreter. It never
// returns source fragments, string bodies unrelated to references, or errors
// containing input. Strings/comments are opaque, including shell script bodies.
func ParseJenkinsfile(source []byte) ParseResult {
	tokens, ok := lex(source)
	if !ok {
		return ParseResult{Unresolved: true}
	}
	result := ParseResult{}
	// Groovy source is not executed. Unsupported method definitions/aliases and
	// interpolation can hide references, so completeness must remain explicit.
	var nesting []string
	for i := 0; i < len(tokens); i++ {
		if tokens[i].interpolated {
			result.Unresolved = true
		}
		if tokens[i].quoted && i+1 < len(tokens) && tokens[i+1].text == "(" {
			result.Unresolved = true
		}
		if tokens[i].quoted {
			continue
		}
		switch tokens[i].text {
		case "(", "[", "{":
			nesting = append(nesting, tokens[i].text)
			if len(nesting) > 64 {
				return ParseResult{Unresolved: true}
			}
		case ")", "]", "}":
			if len(nesting) == 0 {
				return ParseResult{Unresolved: true}
			}
			pair := nesting[len(nesting)-1] + tokens[i].text
			if pair != "()" && pair != "[]" && pair != "{}" {
				return ParseResult{Unresolved: true}
			}
			nesting = nesting[:len(nesting)-1]
		}
	}
	if len(nesting) != 0 {
		return ParseResult{Unresolved: true}
	}
	add := func(t lexeme) {
		if !t.quoted || !t.literal || !referenceID.MatchString(t.text) {
			result.Unresolved = true
			return
		}
		result.References = append(result.References, Reference{t.text, t.line})
	}
	for i, t := range tokens {
		if t.quoted {
			continue
		}
		switch t.text {
		case "library", "Library", "load", "evaluate", "invokeMethod", "methodMissing", "metaClass", "getBinding", "credentialsId":
			// credentialsId is handled by withCredentials below; elsewhere it is
			// not sufficient evidence of a supported binding.
			if t.text == "credentialsId" {
				continue
			}
			result.Unresolved = true
		case "credentials", "withCredentials":
			if i > 0 && (tokens[i-1].text == "." || tokens[i-1].text == "def") {
				result.Unresolved = true
				continue
			}
			if i+1 >= len(tokens) || tokens[i+1].text != "(" {
				result.Unresolved = true
				continue
			}
			end := matching(tokens, i+1)
			if end < 0 {
				result.Unresolved = true
				continue
			}
			args := tokens[i+2 : end]
			if t.text == "credentials" {
				if len(args) == 1 {
					add(args[0])
				} else {
					result.Unresolved = true
				}
				continue
			}
			if len(args) < 2 || args[0].text != "[" || matching(args, 0) != len(args)-1 {
				result.Unresolved = true
				continue
			}
			bindings, valid := splitArguments(args[1 : len(args)-1])
			if !valid {
				result.Unresolved = true
				continue
			}
			for _, binding := range bindings {
				if len(binding) < 3 || binding[0].quoted || !bindingFunction(binding[0].text) || binding[1].text != "(" || matching(binding, 1) != len(binding)-1 {
					result.Unresolved = true
					continue
				}
				fields, valid := splitArguments(binding[2 : len(binding)-1])
				if !valid {
					result.Unresolved = true
					continue
				}
				found := 0
				var candidate *lexeme
				for _, field := range fields {
					if len(field) > 1 && !field[0].quoted && field[0].text == "credentialsId" && field[1].text == ":" {
						found++
						if len(field) == 3 {
							value := field[2]
							candidate = &value
						} else {
							result.Unresolved = true
						}
					}
				}
				if found != 1 {
					result.Unresolved = true
				} else if candidate != nil {
					add(*candidate)
				}
			}
		}
	}
	return result
}

func bindingFunction(s string) bool {
	switch s {
	case "string", "usernamePassword", "usernameColonPassword", "file", "sshUserPrivateKey", "certificate":
		return true
	}
	return false
}
func matching(ts []lexeme, start int) int {
	stack := []string{}
	for i := start; i < len(ts); i++ {
		if ts[i].quoted {
			continue
		}
		switch ts[i].text {
		case "(", "[", "{":
			stack = append(stack, ts[i].text)
		case ")", "]", "}":
			if len(stack) == 0 {
				return -1
			}
			open := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if open+ts[i].text != "()" && open+ts[i].text != "[]" && open+ts[i].text != "{}" {
				return -1
			}
			if len(stack) == 0 {
				return i
			}
		}
	}
	return -1
}
func splitArguments(ts []lexeme) ([][]lexeme, bool) {
	var out [][]lexeme
	start := 0
	for i := 0; i < len(ts); i++ {
		if ts[i].quoted {
			continue
		}
		if ts[i].text == "(" || ts[i].text == "[" || ts[i].text == "{" {
			end := matching(ts, i)
			if end < 0 {
				return nil, false
			}
			i = end
		} else if ts[i].text == "," {
			if i == start {
				return nil, false
			}
			out = append(out, ts[start:i])
			start = i + 1
		}
	}
	if start < len(ts) {
		out = append(out, ts[start:])
	}
	return out, true
}

func lex(source []byte) ([]lexeme, bool) {
	if len(source) > maxJenkinsfileBytes {
		return nil, false
	}
	s := string(source)
	line := 1
	var out []lexeme
	for i := 0; i < len(s); {
		ch := s[i]
		if ch == '\n' {
			line++
			i++
			continue
		}
		if ch == ' ' || ch == '\t' || ch == '\r' {
			i++
			continue
		}
		if strings.HasPrefix(s[i:], "//") {
			for i < len(s) && s[i] != '\n' {
				i++
			}
			continue
		}
		if strings.HasPrefix(s[i:], "/*") {
			end := strings.Index(s[i+2:], "*/")
			if end < 0 {
				return nil, false
			}
			end += i + 4
			line += strings.Count(s[i:end], "\n")
			i = end
			continue
		}
		// Slashy and dollar-slashy strings have ambiguous Groovy interpolation and
		// division semantics. Reject the file rather than inventing references.
		if ch == '/' || strings.HasPrefix(s[i:], "$/") {
			return nil, false
		}
		if ch == '\'' || ch == '"' {
			startLine := line
			quote := string(ch)
			triple := strings.HasPrefix(s[i:], strings.Repeat(quote, 3))
			delimiter := quote
			if triple {
				delimiter = strings.Repeat(quote, 3)
			}
			i += len(delimiter)
			start := i
			literal := !triple
			closed := false
			interpolated := false
			for i < len(s) {
				if s[i] == '\\' {
					literal = false
					i++
					if i < len(s) {
						if s[i] == '\n' {
							line++
						}
						i++
					}
					continue
				}
				if strings.HasPrefix(s[i:], delimiter) {
					closed = true
					break
				}
				if s[i] == '\n' {
					line++
					literal = false
				}
				if ch == '"' && s[i] == '$' {
					literal = false
					interpolated = true
				}
				i++
			}
			if !closed {
				return nil, false
			}
			value := ""
			if literal {
				value = s[start:i]
			}
			out = append(out, lexeme{text: value, quoted: true, literal: literal, line: startLine, interpolated: interpolated})
			i += len(delimiter)
			continue
		}
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_' || ch == '$' {
			start := i
			i++
			for i < len(s) && ((s[i] >= 'a' && s[i] <= 'z') || (s[i] >= 'A' && s[i] <= 'Z') || (s[i] >= '0' && s[i] <= '9') || s[i] == '_' || s[i] == '$') {
				i++
			}
			out = append(out, lexeme{text: s[start:i], line: line})
			continue
		}
		out = append(out, lexeme{text: string(ch), line: line})
		i++
	}
	return out, true
}

type boundedBuffer struct{ buffer bytes.Buffer }

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if len(p) > maxJenkinsfileBytes-b.buffer.Len() {
		return 0, fmt.Errorf("Jenkinsfile exceeds size limit")
	}
	return b.buffer.Write(p)
}
func readPinnedFile(ctx context.Context, file Jenkinsfile) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	// No shell, fetching, checkout, hooks, filters, external diff or textconv.
	// Reject promisor repositories even on older Git versions which do not
	// recognize GIT_NO_LAZY_FETCH. A missing object must never trigger a fetch.
	probe := exec.CommandContext(ctx, "git", "-C", file.Repository, "config", "--get-regexp", `^(extensions\.partialclone|remote\..*\.promisor)$`)
	probe.Stdout = io.Discard
	probe.Stderr = io.Discard
	probeErr := probe.Run()
	var exit *exec.ExitError
	if !errors.As(probeErr, &exit) || exit.ExitCode() != 1 {
		return nil, fmt.Errorf("local non-promisor Git repository required")
	}
	check := exec.CommandContext(ctx, "git", "--no-replace-objects", "-C", file.Repository, "cat-file", "-t", file.Commit)
	check.Env = append(os.Environ(), "GIT_NO_LAZY_FETCH=1", "GIT_TERMINAL_PROMPT=0")
	typ, err := check.Output()
	if err != nil || strings.TrimSpace(string(typ)) != "commit" {
		return nil, fmt.Errorf("pinned Git commit unavailable")
	}
	check = exec.CommandContext(ctx, "git", "--no-replace-objects", "-C", file.Repository, "cat-file", "-t", file.Commit+":"+file.Path)
	check.Env = append(os.Environ(), "GIT_NO_LAZY_FETCH=1", "GIT_TERMINAL_PROMPT=0")
	typ, err = check.Output()
	if err != nil || strings.TrimSpace(string(typ)) != "blob" {
		return nil, fmt.Errorf("pinned Jenkinsfile blob unavailable")
	}
	check = exec.CommandContext(ctx, "git", "--no-replace-objects", "-C", file.Repository, "ls-tree", "--format=%(objectmode)", file.Commit, "--", file.Path)
	check.Env = append(os.Environ(), "GIT_NO_LAZY_FETCH=1", "GIT_TERMINAL_PROMPT=0")
	mode, err := check.Output()
	if err != nil || (strings.TrimSpace(string(mode)) != "100644" && strings.TrimSpace(string(mode)) != "100755") {
		return nil, fmt.Errorf("pinned Jenkinsfile must be a regular file")
	}
	cmd := exec.CommandContext(ctx, "git", "--no-replace-objects", "-C", file.Repository, "show", "--no-ext-diff", "--no-textconv", file.Commit+":"+file.Path)
	cmd.Env = append(os.Environ(), "GIT_NO_LAZY_FETCH=1", "GIT_TERMINAL_PROMPT=0")
	var out boundedBuffer
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("pinned Jenkinsfile unavailable or exceeds size limit")
	}
	return out.buffer.Bytes(), nil
}
