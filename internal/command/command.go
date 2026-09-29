package command

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/grantlinehq/grantline/internal/analyze"
	"github.com/grantlinehq/grantline/internal/bindings"
	"github.com/grantlinehq/grantline/internal/collectors/entra"
	"github.com/grantlinehq/grantline/internal/collectors/github"
	"github.com/grantlinehq/grantline/internal/collectors/jenkins"
	"github.com/grantlinehq/grantline/internal/collectors/kubernetes"
	"github.com/grantlinehq/grantline/internal/collectors/spire"
	"github.com/grantlinehq/grantline/internal/collectors/vault"
	"github.com/grantlinehq/grantline/internal/config"
	"github.com/grantlinehq/grantline/internal/correlate"
	"github.com/grantlinehq/grantline/internal/model"
	"github.com/grantlinehq/grantline/internal/policy"
	"github.com/grantlinehq/grantline/internal/snapshot"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

var Version = "v0.1.0-dev"

func Run(arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 0 {
		printUsage(stderr)
		return 2
	}

	switch arguments[0] {
	case "rotate-key":
		return runRotateKey(arguments[1:], stdout, stderr)
	case "server":
		return runServer(arguments[1:], stdout, stderr)
	case "migrate":
		return runMigrate(arguments[1:], stdout, stderr)
	case "init":
		return runInit(arguments[1:], stdout, stderr)
	case "version":
		if len(arguments) != 1 {
			fmt.Fprintln(stderr, "grantline: version does not accept arguments")
			return 2
		}
		fmt.Fprintf(stdout, "grantline %s\n", Version)
		return 0
	case "analyze":
		return runAnalyze(arguments[1:], stderr)
	case "collect":
		return runCollect(arguments[1:], stderr)
	case "export-spire":
		return runExportSpire(arguments[1:], stdout, stderr)
	case "serve":
		return runServe(arguments[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "grantline: unknown command %q\n", arguments[0])
		printUsage(stderr)
		return 2
	}
}

func runCollect(arguments []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("collect", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "", "path to a Grantline collection config")
	bindingsPath := flags.String("bindings", "", "optional path to explicit Jenkins/Vault declarations")
	outputPath := flags.String("out", "", "path for the JSON snapshot")
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "grantline: collect does not accept positional arguments")
		return 2
	}
	if *configPath == "" || *outputPath == "" {
		fmt.Fprintln(stderr, "grantline: --config and --out are required")
		return 2
	}
	collectorConfig, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "grantline: %v\n", err)
		return 2
	}

	var declarations bindings.Config
	if *bindingsPath != "" {
		declarations, err = bindings.Load(*bindingsPath, collectorConfig.Sources)
		if err != nil {
			fmt.Fprintf(stderr, "grantline: %v\n", err)
			return 2
		}
	}
	collected := model.Snapshot{SchemaVersion: model.SnapshotSchemaVersion}
	for _, source := range collectorConfig.Sources {
		var next model.Snapshot
		switch source.Kind {
		case "spire":
			next, err = (spire.Collector{Config: source.SpireConfig()}).Collect(context.Background())
			if err != nil {
				fmt.Fprintln(stderr, "grantline: invalid SPIRE collection metadata")
				return 2
			}
		case "github":
			next, err = (github.Collector{Config: source.GitHubConfig()}).Collect(context.Background())
			if err != nil {
				fmt.Fprintf(stderr, "grantline: collect GitHub source: %v\n", err)
				return 2
			}
		case "entra":
			next, err = (entra.Collector{Config: source.EntraConfig()}).Collect(context.Background())
			if err != nil {
				fmt.Fprintf(stderr, "grantline: collect Entra source: %v\n", err)
				return 2
			}
		case "jenkins":
			next, err = (jenkins.Collector{Config: source.JenkinsConfig()}).Collect(context.Background())
			if err != nil {
				fmt.Fprintf(stderr, "grantline: collect Jenkins source: %v\n", err)
				return 2
			}
		case "kubernetes":
			client, err := newKubernetesClient(source)
			if err != nil {
				fmt.Fprintf(stderr, "grantline: initialize Kubernetes client: %v\n", err)
				return 2
			}
			next, err = (kubernetes.Collector{Client: client, Source: kubernetes.Source{ID: source.ID, KubeconfigPath: source.KubeconfigPath, Context: source.Context, Scope: source.Scope}}).Collect(context.Background())
			if err != nil {
				fmt.Fprintf(stderr, "grantline: collect Kubernetes source: %v\n", err)
				return 2
			}
		case "vault":
			roles := make([]vault.AuthRole, 0, len(source.AuthRoles))
			for _, role := range source.AuthRoles {
				roles = append(roles, vault.AuthRole{Mount: role.Mount, Name: role.Name, Type: role.Type})
			}
			next, err = (vault.Collector{Config: vault.Config{ID: source.ID, Address: source.Address, TokenEnv: source.TokenEnv, Scope: source.Scope, AuthRoles: roles, Policies: source.Policies}}).Collect(context.Background())
			if err != nil {
				fmt.Fprintf(stderr, "grantline: collect Vault source: %v\n", err)
				return 2
			}
		}
		collected = mergeSnapshots(collected, next)
	}
	collected.CollectedAt = time.Now().UTC()
	bindings := make([]correlate.VaultKubernetesBinding, 0)
	for _, source := range collectorConfig.Sources {
		if source.Kind == "vault" && source.KubernetesSourceID != "" {
			bindings = append(bindings, correlate.VaultKubernetesBinding{VaultSourceID: source.ID, KubernetesSourceID: source.KubernetesSourceID})
		}
	}
	if err := correlate.AddVaultKubernetesTrusts(&collected, bindings); err != nil {
		fmt.Fprintf(stderr, "grantline: correlate Vault Kubernetes trusts: %v\n", err)
		return 2
	}
	correlate.AddJenkinsVaultBindings(&collected, declarations.JenkinsVault)
	correlate.AddGitHubEntraTrusts(&collected)
	if err := snapshot.Write(*outputPath, collected); err != nil {
		fmt.Fprintf(stderr, "grantline: %v\n", err)
		return 2
	}
	if hasIncompleteSources(collected) {
		fmt.Fprintln(stderr, "grantline: snapshot written with incomplete source coverage")
		return 2
	}
	return 0
}

func newKubernetesClient(source config.Source) (kubeclient.Interface, error) {
	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: source.KubeconfigPath},
		&clientcmd.ConfigOverrides{CurrentContext: source.Context},
	)
	restConfig, err := clientConfig.ClientConfig()
	if err != nil {
		return nil, err
	}
	return kubeclient.NewForConfig(restConfig)
}

func mergeSnapshots(left, right model.Snapshot) model.Snapshot {
	left.Entities = append(left.Entities, right.Entities...)
	left.Relationships = append(left.Relationships, right.Relationships...)
	left.Evidence = append(left.Evidence, right.Evidence...)
	left.Sources = append(left.Sources, right.Sources...)
	return left
}

func hasIncompleteSources(snapshot model.Snapshot) bool {
	for _, source := range snapshot.Sources {
		if source.Status != model.SourceOK || !source.Complete || !source.PaginationComplete {
			return true
		}
	}
	return false
}

func runAnalyze(arguments []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("analyze", flag.ContinueOnError)
	flags.SetOutput(stderr)
	snapshotPath := flags.String("snapshot", "", "path to a validated snapshot JSON file")
	policyPath := flags.String("policy", "", "path to an M0 policy YAML file")
	bindingsPath := flags.String("bindings", "", "optional explicit business and SPIRE declarations")
	outputPath := flags.String("out", "", "path for the JSON report")
	failOn := flags.String("fail-on", "", "return exit code 1 at or above: low, medium, high, critical")
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "grantline: analyze does not accept positional arguments")
		return 2
	}
	if *snapshotPath == "" || *policyPath == "" || *outputPath == "" {
		fmt.Fprintln(stderr, "grantline: --snapshot, --policy, and --out are required")
		return 2
	}

	threshold, err := parseSeverity(*failOn)
	if err != nil {
		fmt.Fprintf(stderr, "grantline: %v\n", err)
		return 2
	}
	input, err := snapshot.Load(*snapshotPath)
	if err != nil {
		fmt.Fprintf(stderr, "grantline: %v\n", err)
		return 2
	}
	configuredPolicy, err := policy.Load(*policyPath)
	if err != nil {
		fmt.Fprintf(stderr, "grantline: %v\n", err)
		return 2
	}
	analyzer := analyze.Analyzer{}
	if *bindingsPath != "" {
		var sources []config.Source
		for _, source := range input.Sources {
			sources = append(sources, config.Source{ID: source.ID, Kind: source.Kind, Scope: source.Scope})
		}
		declarations, e := bindings.Load(*bindingsPath, sources)
		if e != nil {
			fmt.Fprintf(stderr, "grantline: %v\n", e)
			return 2
		}
		analyzer.Bindings = &declarations
	}
	report, err := analyzer.Analyze(input, configuredPolicy)
	if err != nil {
		fmt.Fprintf(stderr, "grantline: analyze: %v\n", err)
		return 2
	}
	if err := analyze.WriteReport(*outputPath, report); err != nil {
		fmt.Fprintf(stderr, "grantline: %v\n", err)
		return 2
	}

	unknownRule := false
	for _, result := range report.RuleResults {
		if result.Outcome == model.OutcomeUnknown {
			unknownRule = true
		}
	}
	if !report.Completeness.Complete || unknownRule || len(report.BindingIssues) > 0 {
		fmt.Fprintln(stderr, "grantline: report written with incomplete coverage, unknown checks or unresolved declarations")
		return 2
	}
	if threshold != "" && reportHasFindingAtOrAbove(report, threshold) {
		return 1
	}
	return 0
}

func parseSeverity(value string) (model.Severity, error) {
	if value == "" {
		return "", nil
	}
	severity := model.Severity(strings.ToLower(value))
	if model.SeverityRank(severity) == 0 {
		return "", fmt.Errorf("--fail-on must be one of low, medium, high, critical")
	}
	return severity, nil
}

func reportHasFindingAtOrAbove(report model.Report, threshold model.Severity) bool {
	for _, finding := range report.Findings {
		if model.SeverityRank(finding.Severity) >= model.SeverityRank(threshold) {
			return true
		}
	}
	return false
}

func printUsage(writer io.Writer) {
	fmt.Fprintln(writer, "Persistent workspace: grantline server [--listen ADDRESS] | grantline migrate | grantline init --secrets-dir DIR | grantline rotate-key --new-key-file FILE")
	fmt.Fprintln(writer, "usage: grantline version | grantline collect --config CONFIG [--bindings BINDINGS] --out SNAPSHOT | grantline export-spire --config CONFIG --out EXPORT | grantline analyze --snapshot SNAPSHOT --policy POLICY [--bindings BINDINGS] --out REPORT [--fail-on SEVERITY] | grantline serve --report REPORT [--listen 127.0.0.1:8080]")
}
