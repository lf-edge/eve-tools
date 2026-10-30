// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/sigstore/sigstore-go/pkg/verify"
)

// taggerPredicate is the predicate of release-sign.yml's statement naming
// who pushed the release tag.
type taggerPredicate struct {
	Tag    string `json:"tag"`
	Commit string `json:"commit"`
	Tagger struct {
		Login string `json:"login"`
		ID    int64  `json:"id"`
	} `json:"tagger"`
}

// githubUser is a GitHub account as the API and the tagger statement name it.
type githubUser struct {
	Login string `json:"login"`
	ID    int64  `json:"id"`
}

func (u githubUser) String() string { return fmt.Sprintf("%s (GitHub user ID %d)", u.Login, u.ID) }

// checkTagger verifies the tagger statement in data, signed under the
// release policy with every sums file among its subjects, and returns who
// pushed tag. The statement must name tag and commit.
func (v *verifier) checkTagger(data []byte, sums [][]byte, tag, commit string) (githubUser, error) {
	var p taggerPredicate
	for _, s := range sums {
		r, t, err := v.verifyRelease(data, verify.WithArtifact(strings.NewReader(string(s))))
		if err != nil {
			return githubUser{}, err
		}
		if t != tag {
			return githubUser{}, fmt.Errorf("signed for release %s, not %s", t, tag)
		}
		if r.Statement == nil || r.Statement.PredicateType != v.policy.taggerType {
			return githubUser{}, fmt.Errorf("not a %s statement", v.policy.taggerType)
		}
		pj, err := json.Marshal(r.Statement.Predicate)
		if err != nil {
			return githubUser{}, err
		}
		if err := json.Unmarshal(pj, &p); err != nil {
			return githubUser{}, fmt.Errorf("predicate: %v", err)
		}
	}
	if p.Tag != tag || !strings.EqualFold(p.Commit, commit) {
		return githubUser{}, fmt.Errorf("names %s at %s, not %s at %s", p.Tag, p.Commit, tag, commit)
	}
	if p.Tagger.Login == "" || p.Tagger.ID == 0 {
		return githubUser{}, errors.New("names no tagger")
	}
	return githubUser{Login: p.Tagger.Login, ID: p.Tagger.ID}, nil
}

// runInvocation matches Fulcio's Run Invocation URI for a GitHub Actions run.
var runInvocation = regexp.MustCompile(`^https://github\.com/([^/]+/[^/]+)/actions/runs/([0-9]+)(/attempts/[0-9]+)?$`)

// environmentApprovers returns who approved the policy's deployment
// environment in the signing run. GitHub keeps this only with the run.
func (v *verifier) environmentApprovers(runURI string) ([]githubUser, error) {
	m := runInvocation.FindStringSubmatch(runURI)
	if m == nil || m[1] != v.policy.repo {
		return nil, fmt.Errorf("run %q is not a run of %s", runURI, v.policy.repo)
	}
	var approvals []struct {
		User         githubUser `json:"user"`
		State        string     `json:"state"`
		Environments []struct {
			Name string `json:"name"`
		} `json:"environments"`
	}
	if err := apiGet(fmt.Sprintf("/repos/%s/actions/runs/%s/approvals", m[1], m[2]), &approvals); err != nil {
		return nil, err
	}
	var users []githubUser
	for _, a := range approvals {
		if a.State != "approved" {
			continue
		}
		for _, e := range a.Environments {
			if (v.policy.environment == "" || e.Name == v.policy.environment) && !slices.Contains(users, a.User) {
				users = append(users, a.User)
			}
		}
	}
	return users, nil
}

// reportApprovers prints who pushed the release tag, from the tagger
// statement in dir, and who approved the signing run's environment, from
// GitHub, and warns when either is missing or they are the same account.
// An invalid tagger statement fails; a missing one only warns.
func (v *verifier) reportApprovers(dir, tag string, res assetsResult, sums []string) error {
	var tagger githubUser
	name := tag + ".tagger.sigstore.json"
	data, err := os.ReadFile(filepath.Join(dir, name))
	switch {
	case errors.Is(err, os.ErrNotExist):
		fmt.Fprintf(os.Stderr, "warning: release %s has no %s; who pushed the tag is not recorded\n", tag, name)
	case err != nil:
		return err
	default:
		var contents [][]byte
		for _, s := range sums {
			c, err := os.ReadFile(filepath.Join(dir, s))
			if err != nil {
				return err
			}
			contents = append(contents, c)
		}
		if tagger, err = v.checkTagger(data, contents, tag, res.commit); err != nil {
			return fmt.Errorf("%s: %v", name, err)
		}
		fmt.Printf("OK: tag %s pushed by %s, recorded in Rekor by %s\n", tag, tagger, v.policy.identity)
	}

	approvers, err := v.environmentApprovers(res.runURI)
	switch {
	case err != nil:
		fmt.Fprintf(os.Stderr, "warning: no approvers found for %s: %v\n", res.runURI, err)
	case len(approvers) == 0:
		fmt.Fprintf(os.Stderr, "warning: GitHub records no approval of the %s environment in %s\n", v.policy.environment, res.runURI)
	default:
		for _, a := range approvers {
			fmt.Printf("info: %s environment approved by %s, recorded only by GitHub in %s\n", v.policy.environment, a, res.runURI)
			if tagger.ID != 0 && a.ID == tagger.ID {
				fmt.Fprintf(os.Stderr, "warning: %s both pushed tag %s and approved its signing\n", a.Login, tag)
			}
		}
	}
	if len(v.maintainers) == 0 {
		fmt.Fprintf(os.Stderr, "warning: no maintainer approval checked; -maintainer requires %s.maintainer.sigstore.json\n", tag)
	}
	return nil
}
