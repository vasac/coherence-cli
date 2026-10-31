// Copyright (c) 2026 Oracle and/or its affiliates.
// Licensed under the Universal Permissive License v 1.0 as shown at
// https://oss.oracle.com/licenses/upl.

package main

import (
	"os"
	"path/filepath"
	"testing"
)

const (
	testConstantLinter = "goconst"
	testExistingPath   = "example.go"
	testExistingSource = "source"
	testPriorReason    = "pre-existing"
)

func TestBaselineAcceptsOnlyReviewedOccurrences(t *testing.T) {
	entry := issue{FromLinter: testConstantLinter, Text: "repeated literal", SourceLines: []string{`value := "example"`}}
	entry.Pos.Filename = "pkg/example.go"
	accepted := acceptedIssue{signature{entry.FromLinter, entry.Pos.Filename, entry.Text, entry.SourceLines}, "reviewed existing style debt"}
	if got, _ := unexpectedIssues([]issue{entry}, []acceptedIssue{accepted}); len(got) != 0 {
		t.Fatalf("reviewed issue was rejected: %v", got)
	}
	if _, stale := unexpectedIssues(nil, []acceptedIssue{accepted}); stale != 1 {
		t.Fatal("resolved findings must be removed from the baseline")
	}
	entry.Pos.Line = 200 // Moving reviewed code must not require a new acceptance.
	if got, _ := unexpectedIssues([]issue{entry, entry}, []acceptedIssue{accepted}); len(got) != 1 {
		t.Fatalf("one additional identical occurrence must fail: %v", got)
	}
	for _, change := range []func(*issue){
		func(i *issue) { i.Text += " changed count" },
		func(i *issue) { i.SourceLines = []string{"different source"} },
		func(i *issue) { i.Pos.Filename = "pkg/new.go" },
		func(i *issue) { i.FromLinter = "gosec" },
	} {
		changed := entry
		change(&changed)
		if got, _ := unexpectedIssues([]issue{changed}, []acceptedIssue{accepted}); len(got) != 1 {
			t.Fatalf("new finding was accepted: %v", changed)
		}
	}
}

func TestBaselineRejectsSecurityAndCorrectnessDebt(t *testing.T) {
	accepted := acceptedIssue{signature{"staticcheck", testExistingPath, "ST1005: error string", []string{testExistingSource}}, "reviewed"}
	b := baseline{Version: 1, ToolVersion: "test-version", Review: "review.md", Issues: []acceptedIssue{accepted}}
	if err := validateBaseline(b, b.ToolVersion); err != nil {
		t.Fatal(err)
	}
	for _, entry := range []acceptedIssue{
		{signature{"gosec", testExistingPath, "G306: permissions", []string{testExistingSource}}, testPriorReason},
		{signature{"staticcheck", testExistingPath, "SA1000: invalid regexp", []string{testExistingSource}}, testPriorReason},
		{signature{"errcheck", testExistingPath, "unchecked error", []string{testExistingSource}}, testPriorReason},
		{signature{"revive", testExistingPath, "unreachable-code: unreachable branch", []string{testExistingSource}}, testPriorReason},
		{signature{testConstantLinter, testExistingPath, "literal", []string{testExistingSource}}, ""},
		{signature{testConstantLinter, testExistingPath, "literal", nil}, "missing source"},
	} {
		b.Issues = []acceptedIssue{entry}
		if err := validateBaseline(b, b.ToolVersion); err == nil {
			t.Fatalf("unsafe/incomplete acceptance was allowed: %v", entry)
		}
	}
	b.Issues = nil
	if err := validateBaseline(b, "different-version"); err == nil {
		t.Fatal("tool upgrades must require baseline review")
	}
}

func TestReportErrorsFailClosed(t *testing.T) {
	directory := t.TempDir()
	reportPath, baselinePath := filepath.Join(directory, "report.json"), filepath.Join(directory, "baseline.json")
	if err := os.WriteFile(baselinePath, []byte(`{"version":1,"tool_version":"test-version","review":"review.md","issues":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, contents := range []string{`{`, `{}`, `{"Issues":"invalid"}`} {
		if err := os.WriteFile(reportPath, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
		if err := checkReport(reportPath, baselinePath, "test-version"); err == nil {
			t.Fatalf("invalid report accepted: %s", contents)
		}
	}
	if err := checkReport("missing-report", baselinePath, "test-version"); err == nil {
		t.Fatal("missing report must fail")
	}
	if err := os.WriteFile(reportPath, []byte(`{"Issues":null}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkReport(reportPath, baselinePath, "test-version"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(baselinePath, []byte(`{"unknown":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkReport(reportPath, baselinePath, "test-version"); err == nil {
		t.Fatal("invalid baseline must fail")
	}
}
