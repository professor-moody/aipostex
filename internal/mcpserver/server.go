// Package mcpserver implements a minimal Model Context Protocol server over stdio,
// so an LLM/agent can drive aipostex as a set of tools.
//
// It speaks newline-delimited JSON-RPC 2.0 on stdin/stdout (the MCP stdio
// transport) and handles the core methods: initialize, tools/list, tools/call,
// ping. Tools are registered by the caller; each declares a JSON-Schema input and
// a handler. The package is transport-only — it holds no aipostex logic — so it
// stays small and unit-testable.
//
// Safety model: the SERVER is dumb about danger; the CALLER decides which tools
// to expose and marks mutating/exploit tools so their handlers can require an
// explicit confirmation argument. stdout is the protocol channel, so all logging
// must go to stderr.
package mcpserver

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

// ProtocolVersion is the MCP revision this server advertises.
const ProtocolVersion = "2025-06-18"

// Tool is one callable capability.
type Tool struct {
	Name        string
	Description string
	// InputSchema is a JSON Schema object describing the arguments.
	InputSchema map[string]interface{}
	// Mutating marks tools that change target state (surfaced in listings and to
	// the handler's own gating).
	Mutating bool
	// Handler runs the tool. It returns human/agent-readable text and whether the
	// result represents an error (isError in the MCP tools/call result).
	Handler func(ctx context.Context, args map[string]interface{}) (text string, isError bool)
}

// Server dispatches MCP requests to registered tools.
type Server struct {
	Name    string
	Version string

	mu    sync.RWMutex
	tools []Tool
	index map[string]int
	// Logf receives diagnostics (must NOT be stdout).
	Logf func(format string, a ...interface{})
}

// New creates a server.
func New(name, version string) *Server {
	return &Server{Name: name, Version: version, index: map[string]int{}, Logf: func(string, ...interface{}) {}}
}

// ToolNames returns the registered tool names in registration order, so callers can
// assert what surface they have exposed without going through the protocol.
func (s *Server) ToolNames() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	names := make([]string, 0, len(s.tools))
	for _, t := range s.tools {
		names = append(names, t.Name)
	}
	return names
}

// Tools returns a copy of the registered tools, so callers can build aliases or
// assert on the exposed surface without reaching into the server.
func (s *Server) Tools() []Tool {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Tool, len(s.tools))
	copy(out, s.tools)
	return out
}

// Register adds a tool (last registration of a name wins).
func (s *Server) Register(t Tool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if i, ok := s.index[t.Name]; ok {
		s.tools[i] = t
		return
	}
	s.index[t.Name] = len(s.tools)
	s.tools = append(s.tools, t)
}

// --- JSON-RPC wire types ---

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"` // absent on notifications
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  interface{}     `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

const (
	errMethodNotFound = -32601
	errInvalidParams  = -32602
	errInternal       = -32603
)

// Serve runs the read/dispatch/write loop until in reaches EOF.
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024) // allow large tool args
	enc := json.NewEncoder(out)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var req rpcRequest
		if err := json.Unmarshal(line, &req); err != nil {
			s.Logf("dropping malformed message: %v", err)
			continue
		}
		resp, isNotification := s.handle(ctx, &req)
		if isNotification {
			continue // notifications get no response
		}
		if err := enc.Encode(resp); err != nil {
			return fmt.Errorf("writing response: %w", err)
		}
	}
	return scanner.Err()
}

func (s *Server) handle(ctx context.Context, req *rpcRequest) (rpcResponse, bool) {
	isNotification := len(req.ID) == 0
	resp := rpcResponse{JSONRPC: "2.0", ID: req.ID}

	switch req.Method {
	case "initialize":
		resp.Result = map[string]interface{}{
			"protocolVersion": ProtocolVersion,
			"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
			"serverInfo":      map[string]interface{}{"name": s.Name, "version": s.Version},
		}
	case "notifications/initialized", "initialized":
		return resp, true // notification, no reply
	case "ping":
		resp.Result = map[string]interface{}{}
	case "tools/list":
		resp.Result = map[string]interface{}{"tools": s.listTools()}
	case "tools/call":
		result, rerr := s.callTool(ctx, req.Params)
		if rerr != nil {
			resp.Error = rerr
		} else {
			resp.Result = result
		}
	default:
		if isNotification {
			return resp, true
		}
		resp.Error = &rpcError{Code: errMethodNotFound, Message: "method not found: " + req.Method}
	}
	return resp, isNotification
}

func (s *Server) listTools() []map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]map[string]interface{}, 0, len(s.tools))
	for _, t := range s.tools {
		schema := t.InputSchema
		if schema == nil {
			schema = map[string]interface{}{"type": "object", "properties": map[string]interface{}{}}
		}
		entry := map[string]interface{}{
			"name":        t.Name,
			"description": t.Description,
			"inputSchema": schema,
		}
		if t.Mutating {
			entry["annotations"] = map[string]interface{}{"destructiveHint": true}
		}
		out = append(out, entry)
	}
	return out
}

func (s *Server) callTool(ctx context.Context, rawParams json.RawMessage) (interface{}, *rpcError) {
	var params struct {
		Name      string                 `json:"name"`
		Arguments map[string]interface{} `json:"arguments"`
	}
	if err := json.Unmarshal(rawParams, &params); err != nil {
		return nil, &rpcError{Code: errInvalidParams, Message: "invalid tools/call params"}
	}
	s.mu.RLock()
	idx, ok := s.index[params.Name]
	var tool Tool
	if ok {
		tool = s.tools[idx]
	}
	s.mu.RUnlock()
	if !ok {
		return nil, &rpcError{Code: errMethodNotFound, Message: "unknown tool: " + params.Name}
	}
	if params.Arguments == nil {
		params.Arguments = map[string]interface{}{}
	}
	s.Logf("tools/call %s", params.Name)

	text, isErr := safeCall(ctx, tool, params.Arguments)
	return map[string]interface{}{
		"content": []map[string]interface{}{{"type": "text", "text": text}},
		"isError": isErr,
	}, nil
}

// safeCall runs a handler and converts a panic into an error result rather than
// crashing the server.
func safeCall(ctx context.Context, tool Tool, args map[string]interface{}) (text string, isErr bool) {
	defer func() {
		if r := recover(); r != nil {
			text = fmt.Sprintf("tool %q panicked: %v", tool.Name, r)
			isErr = true
		}
	}()
	return tool.Handler(ctx, args)
}

// StringArg is a helper for handlers: returns the string value of a named arg.
func StringArg(args map[string]interface{}, key string) string {
	if v, ok := args[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// BoolArg returns the bool value of a named arg (false if absent/other type).
func BoolArg(args map[string]interface{}, key string) bool {
	if v, ok := args[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}
