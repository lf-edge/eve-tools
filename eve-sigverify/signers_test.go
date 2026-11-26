// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const signersList = `# login email
alice alice@example.com   # trailing comment
Bob   bob@example.com
malformed-line
three fields here
alice alice@work.example
`

func TestParseSigners(t *testing.T) {
	s := parseSigners([]byte(signersList), "list")
	if s.source != "list" {
		t.Errorf("source %q, want list", s.source)
	}
	if len(s.entries) != 3 {
		t.Fatalf("entries %v, want 3 (comments and lines without two fields ignored)", s.entries)
	}
	tests := []struct {
		email string
		want  []string
	}{
		{"alice@example.com", []string{"alice"}},
		{"BOB@example.com", []string{"Bob"}},
		{"alice@work.example", []string{"alice"}},
		{"malformed-line", nil},
		{"carol@example.com", nil},
	}
	for _, tc := range tests {
		if got := s.logins(tc.email); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("logins(%q) = %v, want %v", tc.email, got, tc.want)
		}
	}
	if got := parseSigners([]byte("a x@example.com\nb x@example.com\n"), "").logins("x@example.com"); len(got) != 2 {
		t.Errorf("one email on two lines: logins %v, want both", got)
	}
}

func TestLoadSigners(t *testing.T) {
	content := base64.StdEncoding.EncodeToString([]byte(signersList))
	// The contents API wraps base64 at 60 columns.
	var wrapped strings.Builder
	for i := 0; i < len(content); i += 60 {
		wrapped.WriteString(content[i:min(i+60, len(content))] + "\n")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/o/r/contents/.github/release-signers":
			json.NewEncoder(w).Encode(map[string]string{"content": wrapped.String(), "encoding": "base64"})
		case "/repos/o/plain/contents/.github/release-signers":
			json.NewEncoder(w).Encode(map[string]string{"content": "x", "encoding": "none"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	saved := githubAPI
	githubAPI = srv.URL
	defer func() { githubAPI = saved }()

	s, err := loadSigners("", "o/r")
	if err != nil {
		t.Fatal(err)
	}
	if got := s.logins("bob@example.com"); !reflect.DeepEqual(got, []string{"Bob"}) {
		t.Errorf("logins from the API = %v, want [Bob]", got)
	}
	if !strings.Contains(s.source, "o/r") {
		t.Errorf("source %q does not name the repository", s.source)
	}
	if _, err := loadSigners("", "o/missing"); err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("missing list: error %v, want 404", err)
	}
	if _, err := loadSigners("", "o/plain"); err == nil || !strings.Contains(err.Error(), "encoding") {
		t.Errorf("unexpected encoding: error %v, want encoding error", err)
	}

	file := filepath.Join(t.TempDir(), "signers")
	if err := os.WriteFile(file, []byte(signersList), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err = loadSigners(file, "o/missing")
	if err != nil {
		t.Fatalf("file given, repository must not be consulted: %v", err)
	}
	if got := s.logins("alice@example.com"); !reflect.DeepEqual(got, []string{"alice"}) || s.source != file {
		t.Errorf("from file: logins %v, source %q", got, s.source)
	}
	if _, err := loadSigners(filepath.Join(t.TempDir(), "absent"), "o/r"); err == nil {
		t.Error("accepted an absent file")
	}
}

func TestApprovalPolicy(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		f := filepath.Join(dir, name)
		if err := os.WriteFile(f, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return f
	}
	list := write("list", "alice alice@example.com\nbob bob@example.com\nalice2 ALICE@example.com\n")
	empty := write("empty", "# nobody\n")
	tests := []struct {
		name    string
		named   []string
		file    string
		want    []string
		wantErr string
	}{
		{name: "every signer by default", file: list, want: []string{"alice@example.com", "bob@example.com"}},
		{name: "named maintainers kept", named: []string{"x@example.com"}, file: list, want: []string{"x@example.com"}},
		{name: "empty list", file: empty, wantErr: "lists no signers"},
		{name: "unreadable list is the policy", file: filepath.Join(dir, "absent"), wantErr: "-no-approval"},
		{name: "unreadable -signers file with named maintainers", named: []string{"x@example.com"}, file: filepath.Join(dir, "absent"), wantErr: "no such file"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := defaultPolicy(forkRepo, forkSigner)
			p.maintainers = tc.named
			s, err := approvalPolicy(&p, tc.file)
			checkErr(t, err, tc.wantErr)
			if err == nil && (!reflect.DeepEqual(p.maintainers, tc.want) || s.source != tc.file) {
				t.Fatalf("maintainers %v, source %q; want %v, %q", p.maintainers, s.source, tc.want, tc.file)
			}
		})
	}
}
