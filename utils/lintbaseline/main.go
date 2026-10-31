// Copyright (c) 2026 Oracle and/or its affiliates.
// Licensed under the Universal Permissive License v 1.0 as shown at
// https://oss.oracle.com/licenses/upl.

// Command lintbaseline checks a full GolangCI-Lint JSON report against reviewed
// style debt. It never accepts security/correctness findings or new occurrences.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

type signature struct {
	Linter string   `json:"linter"`
	Path   string   `json:"path"`
	Text   string   `json:"text"`
	Source []string `json:"source"`
}

type acceptedIssue struct {
	signature
	Reason string `json:"reason"`
}

type baseline struct {
	Version     int             `json:"version"`
	ToolVersion string          `json:"tool_version"`
	Review      string          `json:"review"`
	Issues      []acceptedIssue `json:"issues"`
}

type issue struct {
	FromLinter  string
	Text        string
	SourceLines []string
	Pos         struct {
		Filename string
		Line     int
		Column   int
	}
}

func (s signature) key() string {
	encoded, _ := json.Marshal(s) // Strings and string slices cannot fail to marshal.
	return string(encoded)
}

func validateBaseline(b baseline, version string) error {
	if b.Version != 1 || b.ToolVersion != version || b.Review == "" {
		return fmt.Errorf("lint baseline metadata does not match tool %s; review before updating", version)
	}
	for _, accepted := range b.Issues {
		allowed := accepted.Linter == "goconst"
		if accepted.Linter == "revive" {
			rule, _, _ := strings.Cut(accepted.Text, ":")
			switch rule {
			case "var-naming", "dot-imports", "indent-error-flow", "redefines-builtin-id", "unused-parameter", "error-strings":
				allowed = true
			}
		}
		if accepted.Linter == "staticcheck" {
			code, _, _ := strings.Cut(accepted.Text, ":")
			switch code {
			case "QF1003", "QF1004", "QF1012", "S1007", "S1038", "ST1001", "ST1005", "ST1017":
				allowed = true
			}
		}
		if !allowed || accepted.Path == "" || accepted.Text == "" || len(accepted.Source) == 0 || accepted.Reason == "" {
			return fmt.Errorf("invalid or non-style baseline entry: %s %s", accepted.Linter, accepted.Path)
		}
	}
	return nil
}

func unexpectedIssues(issues []issue, accepted []acceptedIssue) ([]issue, int) {
	remaining := make(map[string]int)
	for _, entry := range accepted {
		remaining[entry.key()]++
	}
	var unexpected []issue
	for _, entry := range issues {
		key := (signature{entry.FromLinter, entry.Pos.Filename, entry.Text, entry.SourceLines}).key()
		if remaining[key] == 0 {
			unexpected = append(unexpected, entry)
		} else {
			remaining[key]--
		}
	}
	stale := 0
	for _, count := range remaining {
		stale += count
	}
	return unexpected, stale
}

func checkReport(reportPath, baselinePath, version string) error {
	// These paths are explicit local inputs supplied by the make recipe.
	// #nosec G703 -- read the build-generated tool report, not a path received from a remote service.
	reportData, err := os.ReadFile(reportPath)
	if err != nil {
		return err
	}
	var report map[string]json.RawMessage
	if err = json.Unmarshal(reportData, &report); err != nil {
		return err
	}
	rawIssues, exists := report["Issues"]
	if !exists {
		return fmt.Errorf("lint report has no Issues field")
	}
	var issues []issue
	if err = json.Unmarshal(rawIssues, &issues); err != nil {
		return err
	}
	// #nosec G703 -- read the explicitly selected, repository-reviewed baseline file.
	baselineData, err := os.ReadFile(baselinePath)
	if err != nil {
		return err
	}
	var b baseline
	decoder := json.NewDecoder(strings.NewReader(string(baselineData)))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&b); err != nil {
		return err
	}
	if err = decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("lint baseline must contain exactly one JSON object")
	}
	if err = validateBaseline(b, version); err != nil {
		return err
	}
	unexpected, stale := unexpectedIssues(issues, b.Issues)
	for _, entry := range unexpected {
		fmt.Fprintf(os.Stderr, "%s:%d:%d: %s (%s)\n", entry.Pos.Filename, entry.Pos.Line, entry.Pos.Column, entry.Text, entry.FromLinter)
	}
	if len(unexpected) != 0 || stale != 0 {
		return fmt.Errorf("%d unreviewed lint issue(s), %d stale baseline entry/entries; fix new issues and remove resolved entries", len(unexpected), stale)
	}
	fmt.Printf("Lint passed: %d reviewed style issue(s), 0 unreviewed issues.\n", len(issues))
	return nil
}

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: lintbaseline REPORT BASELINE TOOL_VERSION")
		os.Exit(2)
	}
	if err := checkReport(os.Args[1], os.Args[2], os.Args[3]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
