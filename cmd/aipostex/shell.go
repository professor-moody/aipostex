package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/professor-moody/aipostex/internal/exitcode"
	"github.com/professor-moody/aipostex/internal/output"
	exploitcommon "github.com/professor-moody/aipostex/pkg/exploit/common"
	exploitmcp "github.com/professor-moody/aipostex/pkg/exploit/mcp"
	"github.com/professor-moody/aipostex/pkg/report"
)

// The operator console `shell` primitive: an interactive REPL against a service
// for the stateful/high-value cases a one-shot `request` doesn't cover — a model
// chat loop, a Jupyter kernel, an MCP tool-caller, an A2A task console. The
// operator drives every turn; the tool holds the transport/session and records
// responses so secrets surface in the loot index on exit. k8s's interactive
// channel is kubectl — handed off as a kubeconfig by the dossier, not reimplemented.

var (
	shellModel     string
	shellKernel    string
	shellMaxTokens int
)

// shellTurn is the result of one operator input line.
type shellTurn struct {
	display  string // printed to stdout (the operator sees this)
	evidence string // recorded raw for the loot index
	title    string
	stage    string
	landed   string
	severity string
	meta     map[string]interface{}
}

type shellMetaCmd struct {
	desc string
	run  func() (string, error)
}

type shellConfig struct {
	source string
	module string
	target string
	prompt string
	intro  []string
	meta   map[string]shellMetaCmd
	exec   func(line string) (shellTurn, error)
}

// shellSession accumulates the findings produced across a REPL so the captured
// responses can be mined for loot when the session ends.
type shellSession struct {
	source   string
	module   string
	target   string
	findings []report.Finding
}

func (s *shellSession) record(t shellTurn) {
	sev := t.severity
	if sev == "" {
		sev = report.SeverityInfo
	}
	meta := t.meta
	if meta == nil {
		meta = map[string]interface{}{}
	}
	meta["module"] = s.module
	meta["action"] = "shell"
	finding := newExploitFinding(s.source, s.target, t.title, sev, t.title, meta)
	finding.Evidence = t.evidence
	stage, landed := t.stage, t.landed
	if stage == "" {
		stage = "access"
	}
	if landed == "" {
		landed = "read-confirmed"
	}
	finding.Metadata = applyStageLanded(finding.Metadata, stage, landed, s.module+"-shell", "shell")
	s.findings = append(s.findings, finding)
}

// runConsoleShell drives the REPL: prompt on stderr, read operator lines from
// stdin, dispatch meta-commands (":") or hand the line to the shell's exec, print
// the response to stdout, and on exit surface any looted credentials.
func runConsoleShell(sc shellConfig) error {
	s := &shellSession{source: sc.source, module: sc.module, target: sc.target}
	for _, line := range sc.intro {
		fmt.Fprintln(stderrWriter, line)
	}
	printShellHelp(sc)

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	turnNum := 0
	for {
		fmt.Fprint(stderrWriter, sc.prompt)
		if !scanner.Scan() {
			break // EOF / ^D
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		switch {
		case line == ":quit" || line == ":exit" || line == ":q":
			fmt.Fprintln(stderrWriter)
			return finishShellSession(s)
		case line == ":help" || line == ":h" || line == ":?":
			printShellHelp(sc)
			continue
		case strings.HasPrefix(line, ":"):
			name := strings.Fields(line)[0]
			mc, ok := sc.meta[name]
			if !ok {
				fmt.Fprintf(stderrWriter, "unknown command %q (:help for commands)\n", name)
				continue
			}
			out, err := mc.run()
			if err != nil {
				fmt.Fprintf(stderrWriter, "error: %v\n", err)
				continue
			}
			if out != "" {
				fmt.Fprintln(os.Stdout, out)
			}
			continue
		}
		turnNum++
		turn, err := sc.exec(line)
		if err != nil {
			// A single failed turn does not end the session — report and continue.
			fmt.Fprintf(stderrWriter, "error: %v\n", err)
			continue
		}
		if turn.display != "" {
			fmt.Fprintln(os.Stdout, turn.display)
		}
		s.record(turn)
	}
	fmt.Fprintln(stderrWriter)
	// Flush any captured loot first, then surface a stdin read error (a real read
	// failure is distinct from a clean EOF/^D, which leaves scanner.Err() nil).
	finishErr := finishShellSession(s)
	if scanErr := scanner.Err(); scanErr != nil {
		return fmt.Errorf("reading input: %w", scanErr)
	}
	return finishErr
}

func printShellHelp(sc shellConfig) {
	var b strings.Builder
	b.WriteString("  commands: :help  :quit")
	for name, mc := range sc.meta {
		b.WriteString(fmt.Sprintf("  %s (%s)", name, mc.desc))
	}
	fmt.Fprintln(stderrWriter, b.String())
}

// finishShellSession mines the session's captured responses for credentials and,
// when the operator asked for capture (-o <file>), writes the recorded findings.
func finishShellSession(s *shellSession) error {
	if len(s.findings) == 0 {
		return nil
	}
	findings := annotateFindingsForOutput(s.findings)
	records := credentialRecordsForReportView(findings)
	if len(records) > 0 {
		fmt.Fprintf(stderrWriter, "── session loot: %d credential(s) ──\n", len(records))
		for _, r := range records {
			fmt.Fprintf(stderrWriter, "  %-22s %s\n", r.Type, r.Value)
		}
		fmt.Fprintln(stderrWriter, "  (captured from responses; `report view <file> --credentials` for the full index)")
	}
	if of := strings.TrimSpace(cfg.OutputFile); of != "" && of != "-" {
		w, err := output.NewJSONLWriter(of)
		if err != nil {
			return err
		}
		defer w.Close()
		if err := w.WriteHeader(); err != nil {
			return err
		}
		for _, f := range findings {
			if err := w.WriteFinding(f); err != nil {
				warnf("writing finding: %v", err)
			}
		}
		if err := w.WriteFooter(findingStats(findings)); err != nil {
			return err
		}
		infof("session captured to %s (%d finding(s))", of, len(findings))
	}
	// A session that captured findings exits non-zero, like every other
	// finding-producing command (writeExploitFindingsWithSummary → FindingsError).
	if len(findings) > 0 {
		return &exitcode.FindingsError{Count: len(findings)}
	}
	return nil
}

// doShellJSON POSTs a JSON payload and returns the raw response, mirroring the
// request primitive's transport (looted/supplied auth or none, capped read).
func doShellJSON(ctx context.Context, url string, headers http.Header, payload any) ([]byte, int, error) {
	client, err := cfg.NewHTTPClient()
	if err != nil {
		return nil, 0, err
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, 0, err
	}
	if headers == nil {
		headers = make(http.Header)
	}
	if headers.Get("Content-Type") == "" {
		headers.Set("Content-Type", "application/json")
	}
	req, err := exploitcommon.NewRequestWithContext(ctx, http.MethodPost, url, headers, bytes.NewReader(data))
	if err != nil {
		return nil, 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, _, err := exploitcommon.ReadAllCapped(resp.Body, exploitcommon.DefaultResponseBodyLimitBytes)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return raw, resp.StatusCode, nil
}

// ---- LLM chat shell -------------------------------------------------------

type chatMsg struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type llmChatProvider struct {
	module     string
	source     string
	target     func() string
	headers    func() (http.Header, error)
	endpoint   string
	modelsPath string // to auto-resolve a model; "" if the server has a single model
	multiTurn  bool
	needsModel bool
	build      func(model string, history []chatMsg, maxTokens int) map[string]any
	reply      func(raw []byte) string
	listModels func(raw []byte) []string
}

type llmChatState struct {
	ctx      context.Context
	provider llmChatProvider
	target   string
	headers  http.Header
	model    string
	maxToks  int
	history  []chatMsg
}

func (cs *llmChatState) exec(line string) (shellTurn, error) {
	cs.history = append(cs.history, chatMsg{Role: "user", Content: line})
	hist := cs.history
	if !cs.provider.multiTurn {
		hist = []chatMsg{{Role: "user", Content: line}}
	}
	payload := cs.provider.build(cs.model, hist, cs.maxToks)
	raw, status, err := doShellJSON(cs.ctx, cs.target+cs.provider.endpoint, cs.headers, payload)
	if err != nil {
		return shellTurn{}, err
	}
	reply := cs.provider.reply(raw)
	// A weak model (or a proxy applying a completion template without stop tokens)
	// can fail to stop at its turn and keep "answering" as both sides, echoing the
	// template's `### User:` / `<|im_start|>` role markers. Feeding that fabricated
	// transcript back on the next turn is what makes the model spiral, so trim it
	// before it enters history or the display. The raw body is still recorded as
	// evidence for the loot index — nothing is dropped from capture.
	cleanReply := trimRunawayTurns(reply)
	if cleanReply != "" {
		cs.history = append(cs.history, chatMsg{Role: "assistant", Content: cleanReply})
	}
	display := cleanReply
	if display == "" {
		// Trimming removed everything (the reply was entirely a runaway turn) or
		// nothing parsed — still show the operator the raw body so nothing is
		// silently swallowed.
		if reply != "" {
			display = reply
		} else {
			display = string(raw)
		}
	}
	// A non-2xx (401/429/500) is not a confirmed inference — it's only reachability.
	stage, landed := "impact", "read-confirmed"
	if status < 200 || status >= 300 {
		stage, landed = "recon", "reachable"
	}
	return shellTurn{
		display:  display,
		evidence: string(raw),
		title:    fmt.Sprintf("chat turn (%s) → %d", modelLabel(cs.model), status),
		stage:    stage,
		landed:   landed,
		severity: report.SeverityInfo,
		meta: map[string]interface{}{
			"provider":        cs.provider.module,
			"model":           cs.model,
			"endpoint":        cs.provider.endpoint,
			"response_status": status,
		},
	}, nil
}

func modelLabel(m string) string {
	if strings.TrimSpace(m) == "" {
		return "default"
	}
	return m
}

// runawayHeaderRe matches a line-anchored chat-template role header (### User:,
// ## Assistant, …). The `##`-prefix requirement is what keeps the words "user"/
// "assistant" appearing in an ordinary reply from being treated as a new turn.
var runawayHeaderRe = regexp.MustCompile(`(?im)^[ \t]*#{2,6}[ \t]*(user|assistant|human|system)\b`)

// runawayTokens are chat-template special tokens a model echoes when it runs past
// its turn (ChatML / Llama-style).
var runawayTokens = []string{"<|user|>", "<|assistant|>", "<|system|>", "<|im_start|>", "<|eot_id|>"}

// trimRunawayTurns cuts a chat reply at the first hallucinated role-turn marker.
// A weak model, or a proxy applying a completion template without stop sequences,
// can fail to stop at its own turn and continue the transcript as both sides; the
// markers are template artifacts, not something a genuine answer contains. A clean
// reply (no marker) is returned unchanged.
func trimRunawayTurns(reply string) string {
	cut := len(reply)
	if loc := runawayHeaderRe.FindStringIndex(reply); loc != nil && loc[0] < cut {
		cut = loc[0]
	}
	lower := strings.ToLower(reply)
	for _, tok := range runawayTokens {
		if i := strings.Index(lower, tok); i >= 0 && i < cut {
			cut = i
		}
	}
	if cut == len(reply) {
		return reply
	}
	return strings.TrimRight(reply[:cut], " \t\r\n")
}

func newLLMChatShellCmd(p llmChatProvider, example string) *cobra.Command {
	cmd := &cobra.Command{
		Use:         "shell",
		Annotations: map[string]string{"aipostex.gated": "true"},
		Short:       fmt.Sprintf("Interactive chat REPL against the %s model (operator console)", p.module),
		Long: fmt.Sprintf(`Open an interactive chat loop against the %s target through the tool.

Type prompts; the tool sends them (with conversation context where the API
supports it) and prints the model's reply. Works authenticated or not. Responses
are captured so any secrets the model discloses surface in the loot index on exit.

Driving inference against the target is an active action, so it requires
--force-exploit.

  aipostex %s`, p.module, example),
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			target := strings.TrimSpace(p.target())
			if target == "" {
				return missingFlagError("target", formatCommandExample(example))
			}
			headers, err := p.headers()
			if err != nil {
				return err
			}
			model, err := resolveChatModel(cmd.Context(), p, exploitcommon.NormalizeTarget(target), headers)
			if err != nil {
				return err
			}
			maxToks := shellMaxTokens
			if maxToks <= 0 {
				maxToks = 256
			}
			cs := &llmChatState{ctx: cmd.Context(), provider: p, target: exploitcommon.NormalizeTarget(target), headers: headers, model: model, maxToks: maxToks}
			return runConsoleShell(shellConfig{
				source: p.source,
				module: p.module,
				target: cs.target,
				prompt: fmt.Sprintf("%s> ", p.module),
				intro:  []string{fmt.Sprintf("%s chat — model %q. Type a prompt; ^D or :quit to exit.", p.module, modelLabel(model))},
				meta: map[string]shellMetaCmd{
					":reset": {desc: "clear conversation history", run: func() (string, error) { cs.history = nil; return "history cleared", nil }},
					":model": {desc: "current model", run: func() (string, error) { return modelLabel(cs.model), nil }},
				},
				exec: cs.exec,
			})
		},
	}
	bindShellChatFlags(cmd)
	return cmd
}

// resolveChatModel uses --model when supplied, else asks the server for its model
// list and picks the first (servers with a single model need no name).
func resolveChatModel(ctx context.Context, p llmChatProvider, target string, headers http.Header) (string, error) {
	if m := strings.TrimSpace(shellModel); m != "" {
		return m, nil
	}
	if !p.needsModel || p.modelsPath == "" {
		return "", nil
	}
	client, err := cfg.NewHTTPClient()
	if err != nil {
		return "", err
	}
	req, err := exploitcommon.NewRequestWithContext(ctx, http.MethodGet, target+p.modelsPath, headers, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("resolving a model from %s: %w (supply --model)", p.modelsPath, err)
	}
	defer resp.Body.Close()
	raw, _, _ := exploitcommon.ReadAllCapped(resp.Body, exploitcommon.SmallResponseLimit)
	models := p.listModels(raw)
	if len(models) == 0 {
		return "", fmt.Errorf("no model found at %s; supply --model", p.modelsPath)
	}
	infof("using model %q (first of %d; override with --model)", models[0], len(models))
	return models[0], nil
}

func bindShellChatFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&shellModel, "model", "", "Model to chat with (default: first advertised by the server)")
	cmd.Flags().IntVar(&shellMaxTokens, "max-tokens", 256, "Max tokens to generate per turn")
}

// ---- reply / model extractors ---------------------------------------------

func replyOpenAI(raw []byte) string {
	var r struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
			Text string `json:"text"`
		} `json:"choices"`
	}
	if json.Unmarshal(raw, &r) == nil && len(r.Choices) > 0 {
		if c := r.Choices[0].Message.Content; c != "" {
			return c
		}
		return r.Choices[0].Text
	}
	return ""
}

func replyOllama(raw []byte) string {
	var r struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		Response string `json:"response"`
	}
	if json.Unmarshal(raw, &r) == nil {
		if r.Message.Content != "" {
			return r.Message.Content
		}
		return r.Response
	}
	return ""
}

func replyHF(raw []byte) string {
	var arr []struct {
		GeneratedText string `json:"generated_text"`
	}
	if json.Unmarshal(raw, &arr) == nil && len(arr) > 0 {
		return arr[0].GeneratedText
	}
	var obj struct {
		GeneratedText string `json:"generated_text"`
	}
	if json.Unmarshal(raw, &obj) == nil {
		return obj.GeneratedText
	}
	return ""
}

func modelsOpenAI(raw []byte) []string {
	var r struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if json.Unmarshal(raw, &r) != nil {
		return nil
	}
	out := make([]string, 0, len(r.Data))
	for _, m := range r.Data {
		if m.ID != "" {
			out = append(out, m.ID)
		}
	}
	return out
}

func modelsOllama(raw []byte) []string {
	var r struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	if json.Unmarshal(raw, &r) != nil {
		return nil
	}
	out := make([]string, 0, len(r.Models))
	for _, m := range r.Models {
		if m.Name != "" {
			out = append(out, m.Name)
		}
	}
	return out
}

func openAIChatPayload(model string, history []chatMsg, maxTokens int) map[string]any {
	return map[string]any{"model": model, "messages": history, "max_tokens": maxTokens}
}

func ollamaChatPayload(model string, history []chatMsg, maxTokens int) map[string]any {
	return map[string]any{"model": model, "messages": history, "stream": false, "options": map[string]any{"num_predict": maxTokens}}
}

func hfGeneratePayload(_ string, history []chatMsg, maxTokens int) map[string]any {
	inputs := ""
	if len(history) > 0 {
		inputs = history[len(history)-1].Content
	}
	return map[string]any{"inputs": inputs, "parameters": map[string]any{"max_new_tokens": maxTokens}}
}

// ---- Jupyter kernel shell -------------------------------------------------

func newJupyterShellCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:         "shell",
		Annotations: map[string]string{"aipostex.gated": "true"},
		Short:       "Interactive Python REPL on a Jupyter kernel (operator console)",
		Long: `Open an interactive Python REPL against a Jupyter kernel through the tool.

Each line you type is executed in the kernel; stdout/results print back. Uses an
existing kernel (--kernel) or the first available, and starts one if none exist.
Code execution is an active operation — requires --force-exploit.

  aipostex jupyter --target http://127.0.0.1:8888 shell --force-exploit`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(jupyterTarget) == "" {
				return missingFlagError("target", formatCommandExample("jupyter --target http://127.0.0.1:8888 shell --force-exploit"))
			}
			if err := requireForceExploit("jupyter shell"); err != nil {
				return err
			}
			client, err := newJupyterClient()
			if err != nil {
				return err
			}
			kernelID := strings.TrimSpace(shellKernel)
			if kernelID == "" {
				kernels, err := client.ListKernels()
				if err != nil {
					return fmt.Errorf("listing kernels: %w", err)
				}
				if len(kernels) > 0 {
					kernelID = kernels[0].ID
				} else {
					k, err := client.StartKernel("python3")
					if err != nil {
						return fmt.Errorf("starting kernel: %w", err)
					}
					kernelID = k.ID
					infof("started kernel %s", kernelID)
				}
			}
			return runConsoleShell(shellConfig{
				source: report.SourceJupyter,
				module: "jupyter",
				target: jupyterTarget,
				prompt: "jupyter> ",
				intro:  []string{fmt.Sprintf("Jupyter kernel %s. Type Python; ^D or :quit to exit.", kernelID)},
				exec: func(line string) (shellTurn, error) {
					out, err := client.Execute(kernelID, line)
					if err != nil {
						return shellTurn{}, err
					}
					return shellTurn{
						display:  out,
						evidence: out,
						title:    fmt.Sprintf("kernel exec on %s", kernelID),
						stage:    "impact",
						landed:   "execution-confirmed",
						severity: report.SeverityHigh,
						meta:     map[string]interface{}{"provider": "jupyter", "kernel": kernelID, "mutating": true},
					}, nil
				},
			})
		},
	}
	cmd.Flags().StringVar(&shellKernel, "kernel", "", "Existing kernel ID (default: first available, or start one)")
	return cmd
}

// ---- MCP tool-caller shell ------------------------------------------------

func newMCPShellCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:         "shell",
		Annotations: map[string]string{"aipostex.gated": "true"},
		Short:       "Interactive MCP tool-caller (operator console)",
		Long: `Open an interactive MCP tool-caller against the server through the tool.

":tools" lists the server's tools. Then invoke one as:  <tool> {"arg":"value"}
(JSON args optional). Results print back. Tool calls can be active operations —
requires --force-exploit.

  aipostex mcp --target http://127.0.0.1:3000 shell --force-exploit`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(mcpTarget) == "" {
				return missingFlagError("target", formatCommandExample("mcp --target http://127.0.0.1:3000 shell --force-exploit"))
			}
			if err := requireForceExploit("mcp shell"); err != nil {
				return err
			}
			client, err := newMCPClient()
			if err != nil {
				return err
			}
			listTools := func() (string, error) {
				tools, err := client.ListTools()
				if err != nil {
					return "", err
				}
				var b strings.Builder
				for _, t := range tools {
					fmt.Fprintf(&b, "  %-24s %s\n", t.Name, t.Description)
				}
				return strings.TrimRight(b.String(), "\n"), nil
			}
			return runConsoleShell(shellConfig{
				source: report.SourceMCP,
				module: "mcp",
				target: mcpTarget,
				prompt: "mcp> ",
				intro:  []string{"MCP tool-caller. `:tools` to list; `<tool> {json args}` to call; ^D or :quit to exit."},
				meta:   map[string]shellMetaCmd{":tools": {desc: "list tools", run: listTools}},
				exec: func(line string) (shellTurn, error) {
					toolName, argsJSON := splitToolInvocation(line)
					args, err := parseToolArgs(argsJSON)
					if err != nil {
						return shellTurn{}, err
					}
					// CallToolResult (not CallTool) so we see isError: a tool that ran but
					// REJECTED the action is reachable, not a confirmed exploitation.
					res, err := client.CallToolResult(toolName, args)
					if err != nil {
						return shellTurn{}, err
					}
					out := res.Text
					if out == "" {
						out = res.Raw
					}
					// Classify by the tool's capability, not blanket execution: a data-returning
					// read tool (read_file/get_environment/list_*) is read-confirmed, a state-changing
					// tool (write/create/delete) is influenced, and only a command-exec tool that ran
					// is execution-confirmed. A rejected call (IsError) is only reachable.
					stage, landed, severity := classifyMCPToolCall(toolName, res.IsError)
					meta := map[string]interface{}{"provider": "mcp", "tool": toolName, "mutating": mcpToolMutates(toolName) && !res.IsError, "tool_error": res.IsError}
					if creds := mcpShellCredentialRecords(out, mcpTarget, "shell:"+toolName); len(creds) > 0 {
						meta["extracted_credentials"] = creds
					}
					return shellTurn{
						display:  out,
						evidence: out,
						title:    fmt.Sprintf("mcp tool call: %s", toolName),
						stage:    stage,
						landed:   landed,
						severity: severity,
						meta:     meta,
					}, nil
				},
			})
		},
	}
	return cmd
}

// mcpToolMutates reports whether an MCP tool name implies a state-changing action (write/exec),
// as opposed to a read/query. Heuristic on the tool name — MCP has no universal capability field.
func mcpToolMutates(toolName string) bool {
	n := strings.ToLower(toolName)
	for _, kw := range []string{"exec", "command", "run", "shell", "eval", "spawn", "system",
		"write", "create", "delete", "update", "set", "put", "upload", "insert", "modify", "remove"} {
		if strings.Contains(n, kw) {
			return true
		}
	}
	return false
}

// classifyMCPToolCall grades a successful MCP tool call by capability: a command-exec tool that
// ran is execution-confirmed; a state-changing (write/create/delete) tool is influenced; a
// data-returning read tool is read-confirmed. A rejected call (isError) is only reachable.
func classifyMCPToolCall(toolName string, isError bool) (stage, landed, severity string) {
	if isError {
		return "recon", "reachable", report.SeverityInfo
	}
	n := strings.ToLower(toolName)
	for _, kw := range []string{"exec", "command", "shell", "eval", "spawn", "system"} {
		if strings.Contains(n, kw) {
			return "impact", "execution-confirmed", report.SeverityHigh
		}
	}
	if mcpToolMutates(toolName) {
		return "impact", "influenced", report.SeverityHigh
	}
	return "impact", "read-confirmed", report.SeverityHigh
}

func mcpShellCredentialRecords(text, target, source string) []map[string]interface{} {
	var records []map[string]interface{}
	seen := make(map[string]struct{})
	for _, env := range exploitmcp.ExtractEnvVarsFromText(text, source) {
		key := strings.TrimSpace(env.Key)
		value := strings.TrimSpace(env.Value)
		if key == "" || value == "" {
			continue
		}
		dedupeKey := key + "\x00" + value
		if _, ok := seen[dedupeKey]; ok {
			continue
		}
		seen[dedupeKey] = struct{}{}
		records = append(records, mcpEnvCredentialRecord(key, value, target, source)...)
	}
	return records
}

func splitToolInvocation(line string) (tool, argsJSON string) {
	line = strings.TrimSpace(line)
	if i := strings.IndexAny(line, " \t{"); i >= 0 {
		return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i:])
	}
	return line, ""
}

func parseToolArgs(argsJSON string) (map[string]any, error) {
	argsJSON = strings.TrimSpace(argsJSON)
	if argsJSON == "" {
		return map[string]any{}, nil
	}
	// Unmarshal into any first: a bare `null`/array/scalar decodes into a nil map
	// without error, so assert an actual JSON object.
	var v any
	if err := json.Unmarshal([]byte(argsJSON), &v); err != nil {
		return nil, fmt.Errorf("arguments must be a JSON object: %w", err)
	}
	args, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("arguments must be a JSON object, got %T", v)
	}
	return args, nil
}

// ---- A2A task console -----------------------------------------------------

func newA2AShellCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:         "shell",
		Annotations: map[string]string{"aipostex.gated": "true"},
		Short:       "Interactive A2A task console (operator console)",
		Long: `Open an interactive task console against an A2A agent through the tool.

Each line is submitted to the agent as a task message; the agent's response
prints back. Submitting tasks is an active operation — requires --force-exploit.

  aipostex a2a --target http://127.0.0.1:8103 shell --force-exploit`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(a2aTarget) == "" {
				return missingFlagError("target", formatCommandExample("a2a --target http://127.0.0.1:8103 shell --force-exploit"))
			}
			if err := requireForceExploit("a2a shell"); err != nil {
				return err
			}
			client, _, err := a2aClientFactory()
			if err != nil {
				return err
			}
			turnNum := 0
			return runConsoleShell(shellConfig{
				source: report.SourceA2A,
				module: "a2a",
				target: a2aTarget,
				prompt: "a2a> ",
				intro:  []string{"A2A task console. Type a message to submit as a task; ^D or :quit to exit."},
				exec: func(line string) (shellTurn, error) {
					turnNum++
					res, err := client.SendTask(fmt.Sprintf("shell-%d", turnNum), line)
					if err != nil {
						return shellTurn{}, err
					}
					landed, stage := "read-confirmed", "impact"
					if res.IsError {
						landed, stage = "reachable", "recon"
					}
					display := res.ResponseRaw
					return shellTurn{
						display:  display,
						evidence: res.ResponseRaw,
						title:    fmt.Sprintf("a2a task %s → %s", safeLabel(res.TaskID), safeLabel(res.Status)),
						stage:    stage,
						landed:   landed,
						severity: report.SeverityInfo,
						meta: map[string]interface{}{
							"provider":    "a2a",
							"task_id":     res.TaskID,
							"task_status": res.Status,
							"rpc_error":   res.IsError,
							"mutating":    true,
						},
					}, nil
				},
			})
		},
	}
	return cmd
}

// registerModuleConsoleShells attaches the `shell` verb to each service whose
// console is a stateful REPL. k8s's interactive channel is kubectl (kubeconfig
// handoff via the dossier), so it has no in-tool shell.
func registerModuleConsoleShells() {
	ollamaCmd.AddCommand(newLLMChatShellCmd(llmChatProvider{
		module: "ollama", source: report.SourceOllama,
		target:   func() string { return ollamaTarget },
		headers:  func() (http.Header, error) { return exploitcommon.ParseHeaderFlags(ollamaHeaders) },
		endpoint: "/api/chat", modelsPath: "/api/tags", multiTurn: true, needsModel: true,
		build: ollamaChatPayload, reply: replyOllama, listModels: modelsOllama,
	}, "ollama --target http://127.0.0.1:11434 shell"))

	openAICompatCmd.AddCommand(newLLMChatShellCmd(llmChatProvider{
		module: "openai-compat", source: report.SourceOpenAICompat,
		target:   func() string { return openAICompatTarget },
		headers:  bearerHeaderResolver(func() []string { return openAICompatHeaders }, func() string { return openAICompatAPIKey }),
		endpoint: "/v1/chat/completions", modelsPath: "/v1/models", multiTurn: true, needsModel: true,
		build: openAIChatPayload, reply: replyOpenAI, listModels: modelsOpenAI,
	}, "openai-compat --target http://127.0.0.1:8000 shell --api-key sk-..."))

	litellmCmd.AddCommand(newLLMChatShellCmd(llmChatProvider{
		module: "litellm", source: report.SourceLiteLLM,
		target:   func() string { return litellmTarget },
		headers:  bearerHeaderResolver(func() []string { return litellmHeaders }, func() string { return litellmAPIKey }),
		endpoint: "/v1/chat/completions", modelsPath: "/v1/models", multiTurn: true, needsModel: true,
		build: openAIChatPayload, reply: replyOpenAI, listModels: modelsOpenAI,
	}, "litellm --target http://127.0.0.1:4000 shell --api-key sk-..."))

	huggingfaceCmd.AddCommand(newLLMChatShellCmd(llmChatProvider{
		module: "huggingface", source: report.SourceHuggingFace,
		target:   func() string { return hfTarget },
		headers:  func() (http.Header, error) { return exploitcommon.ParseHeaderFlags(hfHeaders) },
		endpoint: "/generate", modelsPath: "", multiTurn: false, needsModel: false,
		build: hfGeneratePayload, reply: replyHF, listModels: func([]byte) []string { return nil },
	}, "huggingface --target http://127.0.0.1:8080 shell"))

	jupyterCmd.AddCommand(newJupyterShellCmd())
	mcpCmd.AddCommand(newMCPShellCmd())
	a2aCmd.AddCommand(newA2AShellCmd())
}
