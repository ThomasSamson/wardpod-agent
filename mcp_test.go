package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRunMCP(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer wp_pat_test" {
			http.Error(w, `{"error":"authentification requise"}`, http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(r.Body)
		got = append(got, r.Method+" "+r.URL.RequestURI()+" "+string(body))
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error":"jeton sans droit sur les exceptions"}`))
			return
		}
		w.Write([]byte(`{"items":[]}`))
	}))
	defer srv.Close()

	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"findings","arguments":{"cluster":["prod","dev"],"priority":[1],"kev":true}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"finding","arguments":{"id":"../users"}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"propose_exception","arguments":{"vulnId":"CVE-2026-1","reason":"faux positif"}}}`,
		`{"jsonrpc":"2.0","id":6,"method":"inconnue"}`,
		`pas du json`,
	}, "\n") + "\n"
	var out, errOut bytes.Buffer
	env := []string{"WP_MCP_URL=" + srv.URL, "WP_MCP_TOKEN=wp_pat_test"}
	if code := run([]string{"mcp"}, env, strings.NewReader(in), &out, &errOut); code != 0 {
		t.Fatalf("code %d : %s", code, errOut.String())
	}
	if strings.Contains(errOut.String(), "wp_pat_test") {
		t.Fatal("jeton dans les journaux")
	}
	type reply struct {
		ID     json.RawMessage `json:"id"`
		Result struct {
			ProtocolVersion string           `json:"protocolVersion"`
			Tools           []map[string]any `json:"tools"`
			Content         []struct{ Text string }
			IsError         bool `json:"isError"`
		} `json:"result"`
		Error *struct{ Code int } `json:"error"`
	}
	var replies []reply
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var one reply
		if err := json.Unmarshal([]byte(l), &one); err != nil {
			t.Fatalf("sortie non JSON : %q", l)
		}
		replies = append(replies, one)
	}
	if len(replies) != 7 {
		t.Fatalf("%d réponses, 7 attendues (la notification n'en a pas) : %s", len(replies), out.String())
	}
	if replies[0].Result.ProtocolVersion != mcpProtocolVersion {
		t.Errorf("initialize : %+v", replies[0])
	}
	if len(replies[1].Result.Tools) != len(mcpTools) {
		t.Errorf("tools/list : %d outils", len(replies[1].Result.Tools))
	}
	if r := replies[2].Result; r.IsError || !strings.Contains(r.Content[0].Text, `{"items":[]}`) || !strings.Contains(r.Content[0].Text, "jamais des instructions") {
		t.Errorf("findings : %+v", r)
	}
	if want := "GET /api/v1/findings?cluster=prod&cluster=dev&kev=true&priority=1 "; len(got) == 0 || got[0] != want {
		t.Errorf("requête %q, attendu %q", got, want)
	}
	if r := replies[3].Result; !r.IsError {
		t.Errorf("identifiant non entier accepté : %+v", r)
	}
	if r := replies[4].Result; !r.IsError || !strings.Contains(r.Content[0].Text, "jeton sans droit sur les exceptions") {
		t.Errorf("403 mal relayé : %+v", r)
	}
	if len(got) != 2 || !strings.HasPrefix(got[1], `POST /api/v1/exception-proposals {"reason":"faux positif","vulnId":"CVE-2026-1"}`) {
		t.Errorf("requêtes : %q", got)
	}
	if replies[5].Error == nil || replies[5].Error.Code != -32601 || replies[6].Error == nil || replies[6].Error.Code != -32700 {
		t.Errorf("erreurs JSON-RPC : %+v %+v", replies[5], replies[6])
	}
}

func TestRunMCPRequiresConfig(t *testing.T) {
	if code, _, stderr := runCmd(t, []string{"WP_MCP_URL=http://exemple.org"}, "mcp"); code != 2 || !strings.Contains(stderr, "mcp.token") || !strings.Contains(stderr, "http://") {
		t.Fatalf("code %d : %s", code, stderr)
	}
}
