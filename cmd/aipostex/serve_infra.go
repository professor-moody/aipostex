package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/professor-moody/aipostex/internal/mcpserver"
	"github.com/professor-moody/aipostex/internal/runtimehttp"
	k8sexploit "github.com/professor-moody/aipostex/pkg/exploit/k8s"
	mcpexploit "github.com/professor-moody/aipostex/pkg/exploit/mcp"
	mlflowexploit "github.com/professor-moody/aipostex/pkg/exploit/mlflow"
	ollamaexploit "github.com/professor-moody/aipostex/pkg/exploit/ollama"
	rayexploit "github.com/professor-moody/aipostex/pkg/exploit/ray"
)

// The infrastructure half of the MCP tool surface.
//
// serve.go covers the model and agent layer. These tools cover the infrastructure
// aipostex was built to reach — MCP servers, model runtimes, experiment tracking,
// distributed compute, and the cluster underneath them — because "an agent can drive
// aipostex" was otherwise true only for the bespoke-agent surface.
//
// Every tool here is read-only except where the name says otherwise, and the two
// that are not refuse unless called with "confirm": true, matching the CLI's
// --force-exploit gate. Tools report what they found and nothing more: a listing is
// a listing, not access.

func registerServeInfraTools(srv *mcpserver.Server) {
	arg := mcpserver.StringArg

	target := func(a map[string]interface{}) string { return strings.TrimSpace(arg(a, "target")) }

	// ── MCP servers ──────────────────────────────────────────────────────────
	srv.Register(mcpserver.Tool{
		Name: "mcp_enum",
		Description: "Enumerate an MCP server: its tools, prompts, resources, and resource templates. " +
			"Read-only. Listing a tool is not calling it.",
		InputSchema: strObjSchema(
			[2]string{"target!", "MCP endpoint URL, e.g. http://host:3000"},
		),
		Handler: func(ctx context.Context, a map[string]interface{}) (string, bool) {
			c, err := mcpexploit.NewClient(ctx, target(a), serveTimeout, nil)
			if err != nil {
				return "error: " + err.Error(), true
			}
			defer c.Close()
			if err := c.Initialize(); err != nil {
				return "error: initializing MCP session: " + err.Error(), true
			}
			tools, toolsErr := c.ListTools()
			prompts, _ := c.ListPrompts()
			resources, _ := c.ListResources()
			templates, _ := c.ListResourceTemplates()
			var b strings.Builder
			fmt.Fprintf(&b, "tools=%d prompts=%d resources=%d templates=%d\n",
				len(tools), len(prompts), len(resources), len(templates))
			if toolsErr != nil {
				fmt.Fprintf(&b, "note: listing tools failed: %v\n", toolsErr)
			}
			for _, t := range tools {
				fmt.Fprintf(&b, "[tool] %s — %s\n", t.Name, t.Description)
			}
			for _, p := range prompts {
				fmt.Fprintf(&b, "[prompt] %s — %s\n", p.Name, p.Description)
			}
			for _, r := range resources {
				fmt.Fprintf(&b, "[resource] %s (%s)\n", r.Name, r.URI)
			}
			for _, r := range templates {
				fmt.Fprintf(&b, "[template] %s (%s)\n", r.Name, r.URI)
			}
			return b.String(), false
		},
	})

	srv.Register(mcpserver.Tool{
		Name: "mcp_read",
		Description: "Retrieve an MCP server's resource bodies and prompt templates (resources/read, prompts/get). " +
			"Read-only, but this returns actual data — secrets in it are real.",
		InputSchema: strObjSchema(
			[2]string{"target!", "MCP endpoint URL"},
		),
		Handler: func(ctx context.Context, a map[string]interface{}) (string, bool) {
			c, err := mcpexploit.NewClient(ctx, target(a), serveTimeout, nil)
			if err != nil {
				return "error: " + err.Error(), true
			}
			defer c.Close()
			if err := c.Initialize(); err != nil {
				return "error: initializing MCP session: " + err.Error(), true
			}
			resources, _ := c.ListResources()
			prompts, _ := c.ListPrompts()
			var b strings.Builder
			for _, r := range resources {
				contents, err := c.ReadResource(r.URI)
				if err != nil {
					fmt.Fprintf(&b, "[resource %s] read failed: %v\n", r.URI, err)
					continue
				}
				for _, ct := range contents {
					if ct.Text != "" {
						fmt.Fprintf(&b, "[resource %s]\n%s\n", r.URI, ct.Text)
					}
				}
			}
			for _, p := range prompts {
				var args map[string]any
				if len(p.Arguments) > 0 {
					args = map[string]any{}
					for _, pa := range p.Arguments {
						args[pa.Name] = "aipostex-probe"
					}
				}
				_, msgs, err := c.GetPrompt(p.Name, args)
				if err != nil {
					fmt.Fprintf(&b, "[prompt %s] get failed: %v\n", p.Name, err)
					continue
				}
				for _, m := range msgs {
					fmt.Fprintf(&b, "[prompt %s/%s]\n%s\n", p.Name, m.Role, m.Content.Text)
				}
			}
			if b.Len() == 0 {
				return "the server exposes no readable resources or prompts", false
			}
			return b.String(), false
		},
	})

	srv.Register(mcpserver.Tool{
		Name: "mcp_auth_posture",
		Description: "Assess an MCP endpoint's authorization: whether an unauthenticated request is accepted, " +
			"and what OAuth metadata it advertises. Read-only; does not attempt registration.",
		InputSchema: strObjSchema(
			[2]string{"target!", "MCP endpoint URL"},
		),
		Handler: func(ctx context.Context, a map[string]interface{}) (string, bool) {
			c, err := mcpexploit.NewClient(ctx, target(a), serveTimeout, nil)
			if err != nil {
				return "error: " + err.Error(), true
			}
			defer c.Close()
			enf, err := c.ProbeAuthEnforcement()
			if err != nil {
				return "error: " + err.Error(), true
			}
			var b strings.Builder
			switch {
			case enf.AnonymousAccess:
				fmt.Fprintf(&b, "auth NOT enforced: an unauthenticated initialize was accepted (HTTP %d)\n", enf.StatusCode)
			case enf.Enforced:
				fmt.Fprintf(&b, "auth enforced: unauthenticated request rejected (HTTP %d)\n", enf.StatusCode)
				if enf.WWWAuthenticate != "" {
					fmt.Fprintf(&b, "challenge: %s\n", enf.WWWAuthenticate)
				}
			default:
				fmt.Fprintf(&b, "posture unclear: HTTP %d with no clear accept or reject\n", enf.StatusCode)
			}
			if meta, _ := c.FetchAuthMetadata(enf.ResourceMetaURL); meta.Found {
				fmt.Fprintf(&b, "issuer=%s authorization_endpoint=%s token_endpoint=%s registration_endpoint=%s\n",
					meta.Issuer, meta.AuthorizationEndpoint, meta.TokenEndpoint, meta.RegistrationEndpoint)
			}
			return b.String(), false
		},
	})

	// ── model runtime ────────────────────────────────────────────────────────
	srv.Register(mcpserver.Tool{
		Name: "ollama_enum",
		Description: "Enumerate an Ollama instance: version, available models, and models currently loaded. " +
			"Read-only.",
		InputSchema: strObjSchema(
			[2]string{"target!", "Ollama URL, e.g. http://host:11434"},
		),
		Handler: func(ctx context.Context, a map[string]interface{}) (string, bool) {
			c, err := ollamaexploit.NewClient(ctx, target(a), serveTimeout)
			if err != nil {
				return "error: " + err.Error(), true
			}
			models, err := c.ListModels()
			if err != nil {
				return "error: " + err.Error(), true
			}
			var b strings.Builder
			fmt.Fprintf(&b, "models=%d\n", len(models))
			for _, m := range models {
				fmt.Fprintf(&b, "[model] %s\n", m.Name)
			}
			if running, err := c.ListRunning(); err == nil {
				fmt.Fprintf(&b, "loaded=%d\n", len(running))
				for _, r := range running {
					fmt.Fprintf(&b, "[loaded] %s\n", r.Name)
				}
			}
			return b.String(), false
		},
	})

	srv.Register(mcpserver.Tool{
		Name: "ollama_prompts",
		Description: "Extract the system prompts configured on an Ollama instance's models — the application's " +
			"own instructions. Read-only.",
		InputSchema: strObjSchema(
			[2]string{"target!", "Ollama URL"},
		),
		Handler: func(ctx context.Context, a map[string]interface{}) (string, bool) {
			c, err := ollamaexploit.NewClient(ctx, target(a), serveTimeout)
			if err != nil {
				return "error: " + err.Error(), true
			}
			models, err := c.ListModels()
			if err != nil {
				return "error: " + err.Error(), true
			}
			var b strings.Builder
			found := 0
			for _, m := range models {
				show, err := c.ShowModel(m.Name)
				if err != nil || show == nil {
					continue
				}
				if strings.TrimSpace(show.System) != "" {
					found++
					fmt.Fprintf(&b, "[system prompt: %s]\n%s\n\n", m.Name, show.System)
				}
			}
			if found == 0 {
				return fmt.Sprintf("no system prompts found across %d model(s)", len(models)), false
			}
			return b.String(), false
		},
	})

	// ── ML platform ──────────────────────────────────────────────────────────
	srv.Register(mcpserver.Tool{
		Name:        "mlflow_experiments",
		Description: "List MLflow experiments on a tracking server. Read-only.",
		InputSchema: strObjSchema(
			[2]string{"target!", "MLflow tracking server URL, e.g. http://host:5000"},
		),
		Handler: func(ctx context.Context, a map[string]interface{}) (string, bool) {
			c, err := mlflowexploit.NewClient(ctx, target(a), serveTimeout, nil)
			if err != nil {
				return "error: " + err.Error(), true
			}
			exps, err := c.ListExperiments(50)
			if err != nil {
				return "error: " + err.Error(), true
			}
			var b strings.Builder
			fmt.Fprintf(&b, "experiments=%d\n", len(exps))
			for _, e := range exps {
				fmt.Fprintf(&b, "[experiment] id=%s name=%s\n", e.ID, e.Name)
			}
			return b.String(), false
		},
	})

	srv.Register(mcpserver.Tool{
		Name: "mlflow_runs",
		Description: "List runs for an MLflow experiment, including parameters and artifact locations — " +
			"where storage URIs and connection strings tend to surface. Read-only.",
		InputSchema: strObjSchema(
			[2]string{"target!", "MLflow tracking server URL"},
			[2]string{"experiment_id!", "Experiment id to list runs for"},
		),
		Handler: func(ctx context.Context, a map[string]interface{}) (string, bool) {
			c, err := mlflowexploit.NewClient(ctx, target(a), serveTimeout, nil)
			if err != nil {
				return "error: " + err.Error(), true
			}
			runs, err := c.ListRuns(arg(a, "experiment_id"), 25)
			if err != nil {
				return "error: " + err.Error(), true
			}
			var b strings.Builder
			fmt.Fprintf(&b, "runs=%d\n", len(runs))
			for _, r := range runs {
				fmt.Fprintf(&b, "[run] id=%s status=%s artifact_uri=%s\n", r.ID, r.Status, r.ArtifactURI)
				for k, v := range r.Params {
					fmt.Fprintf(&b, "    param %s=%s\n", k, v)
				}
			}
			return b.String(), false
		},
	})

	srv.Register(mcpserver.Tool{
		Name: "ray_jobs",
		Description: "List jobs on a Ray dashboard, including entrypoints and runtime environments — " +
			"where cluster credentials are frequently passed. Read-only.",
		InputSchema: strObjSchema(
			[2]string{"target!", "Ray dashboard URL, e.g. http://host:8265"},
		),
		Handler: func(ctx context.Context, a map[string]interface{}) (string, bool) {
			c, err := rayexploit.NewClient(ctx, target(a), serveTimeout, nil)
			if err != nil {
				return "error: " + err.Error(), true
			}
			jobs, err := c.ListJobs()
			if err != nil {
				return "error: " + err.Error(), true
			}
			var b strings.Builder
			fmt.Fprintf(&b, "jobs=%d\n", len(jobs))
			for _, j := range jobs {
				fmt.Fprintf(&b, "[job] id=%s status=%s entrypoint=%s\n", j.ID, j.Status, j.Entrypoint)
			}
			return b.String(), false
		},
	})

	// ── cluster ──────────────────────────────────────────────────────────────
	srv.Register(mcpserver.Tool{
		Name: "k8s_posture",
		Description: "Assess what an unauthenticated (or supplied-token) identity may do against a Kubernetes " +
			"API server, and list the namespaces it can see. Read-only.",
		InputSchema: strObjSchema(
			[2]string{"target!", "Kubernetes API server URL, e.g. https://host:6443"},
			[2]string{"token", "Optional bearer token to authenticate as"},
			[2]string{"namespace", "Namespace to scope the access review to (default: default)"},
			[2]string{"insecure", "Set to true to skip TLS verification (clusters commonly use a self-signed API-server certificate)"},
		),
		Handler: func(ctx context.Context, a map[string]interface{}) (string, bool) {
			headers := http.Header{}
			if tok := arg(a, "token"); tok != "" {
				headers.Set("Authorization", "Bearer "+tok)
			}
			c, err := k8sexploit.NewClient(ctx, target(a), serveTimeout, headers)
			if err != nil {
				return "error: " + err.Error(), true
			}
			// k3s and most self-managed clusters present a self-signed API-server
			// certificate. Insecure alone only covers the exec dialer, so the HTTP
			// client has to be rebuilt too or every ordinary call fails verification.
			if mcpserver.BoolArg(a, "insecure") {
				c.Insecure = true
				hc, hcErr := runtimehttp.NewClient(runtimehttp.Options{Timeout: serveTimeout, Insecure: true})
				if hcErr != nil {
					return "error: building insecure HTTP client: " + hcErr.Error(), true
				}
				c.HTTPClient = hc
			}
			var b strings.Builder
			ns, nsErr := c.ListNamespaces()
			if nsErr != nil {
				fmt.Fprintf(&b, "namespaces: not listable (%v)\n", nsErr)
			} else {
				fmt.Fprintf(&b, "namespaces=%d: %s\n", len(ns), strings.Join(ns, ", "))
			}
			scope := arg(a, "namespace")
			if scope == "" {
				scope = "default"
			}
			if review, err := c.SelfSubjectRulesReview(scope); err == nil && review != nil {
				fmt.Fprintf(&b, "access review in %s: authenticated=%t rules=%d\n",
					scope, review.Authenticated, len(review.Rules))
				if len(review.Verbs) > 0 {
					fmt.Fprintf(&b, "    verbs: %s\n", strings.Join(review.Verbs, ", "))
				}
				if len(review.Resources) > 0 {
					fmt.Fprintf(&b, "    resources: %s\n", strings.Join(review.Resources, ", "))
				}
			} else if err != nil {
				fmt.Fprintf(&b, "access review in %s failed: %v\n", scope, err)
			}
			if b.Len() == 0 {
				return "no cluster information was readable with this identity", false
			}
			return b.String(), false
		},
	})
}
