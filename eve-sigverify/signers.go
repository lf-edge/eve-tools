// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

// releaseSigners is a repository's list of release signers: the lines
// "<GitHub login> <email>" of .github/release-signers, where the email is the
// one the signer picks at the Sigstore login. An approval's certificate names
// only that email, so the login comes from this list and is exactly as
// trustworthy as it. The zero value is an empty list with no source.
type releaseSigners struct {
	entries [][2]string // login, email
	source  string      // where the list came from, for messages
}

// parseSigners reads the lines of a release signers list. Text after # is a
// comment, and a line that does not have exactly two fields is ignored.
func parseSigners(data []byte, source string) releaseSigners {
	s := releaseSigners{source: source}
	for _, line := range strings.Split(string(data), "\n") {
		line, _, _ = strings.Cut(line, "#")
		if f := strings.Fields(line); len(f) == 2 {
			s.entries = append(s.entries, [2]string{f[0], f[1]})
		}
	}
	return s
}

// logins returns the GitHub logins the list gives for email.
func (s releaseSigners) logins(email string) []string {
	var out []string
	for _, e := range s.entries {
		if strings.EqualFold(e[1], email) {
			out = append(out, e[0])
		}
	}
	return out
}

// loadSigners reads the release signers from file, or, when file is empty,
// from .github/release-signers on the default branch of repo through the
// GitHub API.
func loadSigners(file, repo string) (releaseSigners, error) {
	if file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			return releaseSigners{}, err
		}
		return parseSigners(data, file), nil
	}
	var f struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	if err := apiGet(fmt.Sprintf("/repos/%s/contents/.github/release-signers", repo), &f); err != nil {
		return releaseSigners{}, err
	}
	if f.Encoding != "base64" {
		return releaseSigners{}, fmt.Errorf("release-signers of %s: unexpected encoding %q", repo, f.Encoding)
	}
	data, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(f.Content, "\n", ""))
	if err != nil {
		return releaseSigners{}, fmt.Errorf("release-signers of %s: %v", repo, err)
	}
	return parseSigners(data, ".github/release-signers of "+repo), nil
}
