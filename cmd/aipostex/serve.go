package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/professor-moody/aipostex/internal/config"
	"github.com/professor-moody/aipostex/internal/mcpserver"
	"github.com/professor-moody/aipostex/internal/modelfingerprint"
	agentexploit "github.com/professor-moody/aipostex/pkg/exploit/agent"
	openaicompat "github.com/professor-moody/aipostex/pkg/exploit/openaicompat"
	ragexploit "github.com/professor-moody/aipostex/pkg/exploit/rag"
)

var serveTimeout time.Duration

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run aipostex as an MCP server (stdio) so an LLM/agent can drive it",
	Long: `Expose a curated set of aipostex capabilities as Model Context Protocol tools over stdio,
so an LLM or agent framework can drive reconnaissance and bounded exploitation.

Safety model:
  - Recon/enumeration tools (fingerprint, probe, enum, extract, query, map) are read-only and
    exposed directly.
  - Mutating tools (e.g. rag_poison) are gated: the handler refuses unless called with
    "confirm": true, so an autonomous model cannot mutate a target without an explicit signal.
  - Every tool call is audit-logged to stderr (stdout is the protocol channel).

Wire it into an MCP client (e.g. Claude) as a stdio server running "aipostex serve".`,
	Example: formatCommandExample("serve"),
	RunE:    runServe,
}

func init() {
	serveCmd.Flags().DurationVar(&serveTimeout, "timeout", 90*time.Second, "Per-call HTTP timeout for tool handlers")
	serveCmd.GroupID = operationsGroupID
	rootCmd.AddCommand(serveCmd)
}

func runServe(cmd *cobra.Command, args []string) error {
	srv := mcpserver.New("aipostex", config.Version)
	srv.Logf = func(format string, a ...interface{}) {
		fmt.Fprintf(os.Stderr, "[aipostex-mcp] "+format+"\n", a...)
	}
	registerServeTools(srv)
	registerServeInfraTools(srv)
	fmt.Fprintln(os.Stderr, "[aipostex-mcp] serving on stdio; tools registered. Ctrl-C to stop.")
	return srv.Serve(currentContext(), os.Stdin, os.Stdout)
}

// strObjSchema builds a simple object schema from (name, description) pairs where
// names ending in "!" are marked required.
func strObjSchema(pairs ...[2]string) map[string]interface{} {
	props := map[string]interface{}{}
	var required []string
	for _, p := range pairs {
		name, desc := p[0], p[1]
		if strings.HasSuffix(name, "!") {
			name = strings.TrimSuffix(name, "!")
			required = append(required, name)
		}
		props[name] = map[string]interface{}{"type": "string", "description": desc}
	}
	schema := map[string]interface{}{"type": "object", "properties": props}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

func registerServeTools(srv *mcpserver.Server) {
	arg := mcpserver.StringArg

	// --- behavioral model fingerprint (OpenAI-compatible endpoint) ---
	srv.Register(mcpserver.Tool{
		Name:        "fingerprint_model",
		Description: "Behaviorally fingerprint the model family behind an OpenAI-compatible endpoint (identity, contradiction, knowledge-cutoff). Read-only.",
		InputSchema: strObjSchema([2]string{"target!", "Endpoint base URL, e.g. http://host:8000"}, [2]string{"model", "Model id (optional; best-scored model used if empty)"}),
		Handler: func(ctx context.Context, a map[string]interface{}) (string, bool) {
			c, err := openaicompat.NewClient(ctx, arg(a, "target"), serveTimeout, nil)
			if err != nil {
				return "error: " + err.Error(), true
			}
			resolved, err := c.ResolveModel(arg(a, "model"))
			if err != nil {
				return "error resolving model: " + err.Error(), true
			}
			res := modelfingerprint.Identify(modelfingerprint.Options{
				Send: func(p string) (string, error) { return c.Ask(resolved, p) },
			})
			return fmt.Sprintf("model=%s\n%s", resolved, res.Evidence), false
		},
	})

	// --- bespoke agent tools (all read-only) ---
	agentClient := func(ctx context.Context, a map[string]interface{}) *agentexploit.Client {
		c := agentexploit.NewClient(ctx, arg(a, "target"), serveTimeout, nil)
		if t := arg(a, "request_template"); t != "" {
			c.RequestTemplate = t
		}
		if f := arg(a, "response_field"); f != "" {
			c.ResponseFields = []string{f}
		}
		return c
	}
	agentSchema := func(extra ...[2]string) map[string]interface{} {
		base := [][2]string{
			{"target!", "Bespoke agent chat endpoint, e.g. http://host:8110/chat"},
			{"request_template", `Optional JSON body with a {{PROMPT}} placeholder`},
			{"response_field", "Optional dot-path to the reply text in the response"},
		}
		return strObjSchema(append(base, extra...)...)
	}

	srv.Register(mcpserver.Tool{
		Name: "agent_probe", Description: "Send a benign message to a bespoke /chat agent and capture its reply. Read-only.",
		InputSchema: agentSchema(),
		Handler: func(ctx context.Context, a map[string]interface{}) (string, bool) {
			reply, status, err := agentClient(ctx, a).AskRaw("Hello — in one sentence, what do you do?")
			if err != nil {
				return "error: " + err.Error(), true
			}
			return fmt.Sprintf("http=%d\n%s", status, reply), false
		},
	})
	srv.Register(mcpserver.Tool{
		Name: "agent_enum", Description: "Ask a bespoke agent to list its tools/capabilities. Read-only.",
		InputSchema: agentSchema(),
		Handler: func(ctx context.Context, a map[string]interface{}) (string, bool) {
			reply, err := agentClient(ctx, a).Ask("List every tool, function, or capability you have access to, with a short description of each.")
			if err != nil {
				return "error: " + err.Error(), true
			}
			tools := agentexploit.ExtractToolMentions(reply)
			return fmt.Sprintf("advertised_tools=%s\n\n%s", strings.Join(tools, ", "), reply), false
		},
	})
	srv.Register(mcpserver.Tool{
		Name: "agent_extract", Description: "Attempt system-prompt/config extraction against a bespoke agent, running an output-filter-bypass matrix. Read-only.",
		InputSchema: agentSchema([2]string{"goal", "Optional custom extraction goal"}),
		Handler: func(ctx context.Context, a map[string]interface{}) (string, bool) {
			res := agentexploit.ExtractWithBypass(agentClient(ctx, a).Ask, arg(a, "goal"))
			out := res.Verdict
			if res.LeakedContent != "" {
				out += "\n\nrecovered:\n" + res.LeakedContent
			}
			return out, false
		},
	})
	srv.Register(mcpserver.Tool{
		Name: "agent_fingerprint", Description: "Behaviorally fingerprint the model family behind a bespoke agent. Read-only.",
		InputSchema: agentSchema(),
		Handler: func(ctx context.Context, a map[string]interface{}) (string, bool) {
			c := agentClient(ctx, a)
			res := modelfingerprint.Identify(modelfingerprint.Options{Send: c.Ask})
			return res.Evidence, false
		},
	})

	// --- black-box RAG tools ---
	ragClient := func(ctx context.Context, a map[string]interface{}) *ragexploit.Client {
		c := ragexploit.NewClient(ctx, arg(a, "target"), serveTimeout, nil)
		if p := arg(a, "query_path"); p != "" {
			c.QueryPath = p
		}
		if p := arg(a, "ingest_path"); p != "" {
			c.IngestPath = p
		}
		return c
	}
	srv.Register(mcpserver.Tool{
		Name: "rag_query", Description: "Query a black-box RAG app and return the answer plus source citations (and any leaked secrets). Read-only.",
		InputSchema: strObjSchema(
			[2]string{"target!", "RAG app base URL, e.g. http://host:8091"},
			[2]string{"query!", "The query to send"},
			[2]string{"query_path", "Optional query endpoint path (default /query)"},
		),
		Handler: func(ctx context.Context, a map[string]interface{}) (string, bool) {
			res, err := ragClient(ctx, a).Query(arg(a, "query"))
			if err != nil {
				return "error: " + err.Error(), true
			}
			var b strings.Builder
			fmt.Fprintf(&b, "answer: %s\n", res.Answer)
			for _, s := range res.Sources {
				fmt.Fprintf(&b, "[source] %s (%s) score=%.3f\n  %s\n", s.Title, s.ChunkID, s.Score, s.Text)
			}
			return b.String(), false
		},
	})
	srv.Register(mcpserver.Tool{
		Name: "rag_map", Description: "Map a black-box RAG knowledge base via a recon-query battery, flagging documents that leak secrets. Read-only.",
		InputSchema: strObjSchema([2]string{"target!", "RAG app base URL, e.g. http://host:8091"}),
		Handler: func(ctx context.Context, a map[string]interface{}) (string, bool) {
			km, _ := ragexploit.MapKnowledgeBase(ragClient(ctx, a).Query)
			return km.Evidence, false
		},
	})
	srv.Register(mcpserver.Tool{
		Name:        "rag_poison",
		Mutating:    true,
		Description: "Ingest an attacker document into a RAG knowledge base and verify it surfaces on a trigger query. MUTATING — requires \"confirm\": true.",
		InputSchema: strObjSchema(
			[2]string{"target!", "RAG app base URL"},
			[2]string{"title!", "Title/filename of the poisoned document"},
			[2]string{"content!", "Content of the poisoned document"},
			[2]string{"trigger_query", "Query to verify the poison surfaces (optional)"},
			[2]string{"confirm", `Must be the boolean true to authorize this mutating action`},
		),
		Handler: func(ctx context.Context, a map[string]interface{}) (string, bool) {
			if !mcpserver.BoolArg(a, "confirm") {
				return "refused: rag_poison mutates the target knowledge base; call again with \"confirm\": true to authorize.", true
			}
			c := ragClient(ctx, a)
			out, status, err := c.Ingest(arg(a, "title"), arg(a, "content"))
			if err != nil {
				return "error: " + err.Error(), true
			}
			result := fmt.Sprintf("ingest http=%d: %s", status, out)
			if tq := arg(a, "trigger_query"); tq != "" {
				res, qErr := c.Query(tq)
				surfaced := false
				if qErr == nil {
					for _, s := range res.Sources {
						if strings.EqualFold(s.Title, arg(a, "title")) {
							surfaced = true
						}
					}
				}
				result += fmt.Sprintf("\ntrigger_query surfaced=%t", surfaced)
			}
			return result, false
		},
	})
}
