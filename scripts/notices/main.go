// Command notices writes THIRD_PARTY_NOTICES.txt: the licence of every module compiled into the
// CertSmith binary, as the licences require when a binary is distributed.
//
//	go run ./scripts/notices          write internal/web/static/THIRD_PARTY_NOTICES.txt
//	go run ./scripts/notices -check   fail if the file is out of date (used by CI)
//
// It also enforces a policy: every dependency must carry a licence on the allowlist below. A new
// dependency under a copyleft or unrecognised licence fails the build until someone decides.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const output = "internal/web/static/THIRD_PARTY_NOTICES.txt"

// Licences that may be bundled in a binary released under MIT. MPL-2.0 is file-level copyleft: it is
// acceptable for unmodified dependencies, with the notice and a pointer to the source.
var allowed = map[string]bool{
	"MIT": true, "Apache-2.0": true, "BSD-2-Clause": true, "BSD-3-Clause": true, "ISC": true, "MPL-2.0": true,
}

type module struct {
	Path, Version, Dir string
	License            string
	Texts              []licenseFile
}

type licenseFile struct{ Name, Text string }

var licenseName = regexp.MustCompile(`(?i)^(licen[sc]e|copying|notice|unlicense)(\..*)?$`)

// classify names a licence from the start of its text. The order matters: the MPL-2.0 text itself
// mentions the GNU licences in its "Secondary License" definition, so it is tested first and the
// GNU licences are recognised only by their own title.
func classify(text string) string {
	head := text
	if len(head) > 8000 {
		head = head[:8000]
	}
	title := strings.ToUpper(strings.Join(strings.Fields(firstLines(head, 6)), " "))
	switch {
	case strings.Contains(head, "Mozilla Public License"):
		return "MPL-2.0"
	case strings.Contains(title, "GNU AFFERO"):
		return "AGPL"
	case strings.Contains(title, "GNU LESSER"):
		return "LGPL"
	case strings.Contains(title, "GNU GENERAL PUBLIC"):
		return "GPL"
	case strings.Contains(head, "Apache License") && strings.Contains(head, "Version 2.0"):
		return "Apache-2.0"
	case strings.Contains(head, "Permission is hereby granted, free of charge"):
		return "MIT"
	case strings.Contains(head, "Redistribution and use in source and binary forms"):
		if regexp.MustCompile(`(?i)neither the name|endorse or promote`).MatchString(head) {
			return "BSD-3-Clause"
		}
		return "BSD-2-Clause"
	case regexp.MustCompile(`(?i)Permission to use, copy, modify, and/or distribute|ISC License`).MatchString(head):
		return "ISC"
	}
	return "UNKNOWN"
}

func firstLines(s string, n int) string {
	lines := strings.SplitN(s, "\n", n+1)
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}

// modules lists the modules compiled into the binary for each platform CertSmith is released for.
func modules() (map[string]*module, string, error) {
	out := map[string]*module{}
	var goroot string
	for _, arch := range []string{"amd64", "arm64"} {
		cmd := exec.Command("go", "list", "-deps", "-f", "{{with .Module}}{{.Path}}|{{.Version}}|{{.Dir}}|{{.Main}}{{end}}", "./cmd/certsmith")
		cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
		b, err := cmd.Output()
		if err != nil {
			return nil, "", fmt.Errorf("go list: %w", err)
		}
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Split(strings.TrimSpace(line), "|")
			if len(f) != 4 || f[0] == "" || f[3] == "true" {
				continue
			}
			out[f[0]] = &module{Path: f[0], Version: f[1], Dir: f[2]}
		}
	}
	b, err := exec.Command("go", "env", "GOROOT").Output()
	if err != nil {
		return nil, "", err
	}
	goroot = strings.TrimSpace(string(b))
	return out, goroot, nil
}

func read(m *module) error {
	entries, err := os.ReadDir(m.Dir)
	if err != nil {
		return fmt.Errorf("%s: %w", m.Path, err)
	}
	for _, e := range entries {
		if e.IsDir() || !licenseName.MatchString(e.Name()) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(m.Dir, e.Name()))
		if err != nil {
			return err
		}
		text := strings.TrimSpace(strings.ReplaceAll(string(b), "\r\n", "\n"))
		m.Texts = append(m.Texts, licenseFile{e.Name(), text})
		// the licence is named from the licence file, not from a NOTICE file
		if strings.HasPrefix(strings.ToUpper(e.Name()), "NOTICE") {
			continue
		}
		if m.License == "" || m.License == "UNKNOWN" {
			m.License = classify(text)
		}
	}
	sort.Slice(m.Texts, func(i, j int) bool { return m.Texts[i].Name < m.Texts[j].Name })
	if len(m.Texts) == 0 {
		return fmt.Errorf("%s %s: no licence file found", m.Path, m.Version)
	}
	return nil
}

func source(path, version string) string {
	if strings.HasPrefix(path, "github.com/") || strings.HasPrefix(path, "gitlab.com/") {
		return "https://" + path
	}
	return "https://pkg.go.dev/" + path + "@" + version
}

func build() ([]byte, error) {
	mods, goroot, err := modules()
	if err != nil {
		return nil, err
	}
	var list []*module
	var problems []string
	for _, m := range mods {
		if err := read(m); err != nil {
			problems = append(problems, err.Error())
			continue
		}
		if !allowed[m.License] {
			problems = append(problems, fmt.Sprintf("%s %s: licence %q is not on the allowlist", m.Path, m.Version, m.License))
		}
		list = append(list, m)
	}
	// the Go standard library and runtime are part of every binary
	std := &module{Path: "Go standard library and runtime", Version: "", Dir: goroot}
	if b, err := os.ReadFile(filepath.Join(goroot, "LICENSE")); err == nil {
		std.Texts = []licenseFile{{"LICENSE", strings.TrimSpace(string(b))}}
		std.License = classify(std.Texts[0].Text)
	} else {
		problems = append(problems, "Go standard library: "+err.Error())
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return nil, fmt.Errorf("licence policy:\n  %s", strings.Join(problems, "\n  "))
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Path < list[j].Path })

	var b bytes.Buffer
	fmt.Fprintf(&b, "CertSmith third-party notices\n=============================\n\n")
	fmt.Fprintf(&b, "CertSmith includes the software listed below. Each component is distributed under its own\n")
	fmt.Fprintf(&b, "licence, reproduced in full after the list. Components under the Mozilla Public License 2.0\n")
	fmt.Fprintf(&b, "are used unmodified; their source code is available at the address given for each.\n\n")
	fmt.Fprintf(&b, "This file is generated by `go run ./scripts/notices` from the licence files of the modules\n")
	fmt.Fprintf(&b, "compiled into the binary. Do not edit it by hand.\n\n")
	counts := map[string]int{}
	for _, m := range list {
		counts[m.License]++
	}
	counts[std.License]++
	var names []string
	for k := range counts {
		names = append(names, k)
	}
	sort.Strings(names)
	fmt.Fprintf(&b, "Summary: %d components", len(list)+1)
	for _, k := range names {
		fmt.Fprintf(&b, ", %d %s", counts[k], k)
	}
	fmt.Fprintf(&b, ".\n\n")
	fmt.Fprintf(&b, "Components\n----------\n\n")
	all := append([]*module{std}, list...)
	for _, m := range all {
		v := m.Version
		if v != "" {
			v = " " + v
		}
		fmt.Fprintf(&b, "  %-12s %s%s\n", m.License, m.Path, v)
	}
	for _, m := range all {
		v := m.Version
		if v != "" {
			v = " " + v
		}
		fmt.Fprintf(&b, "\n\n================================================================================\n")
		fmt.Fprintf(&b, "%s%s\nLicence: %s\n", m.Path, v, m.License)
		if m != std {
			fmt.Fprintf(&b, "Source:  %s\n", source(m.Path, m.Version))
		} else {
			fmt.Fprintf(&b, "Source:  https://go.dev/\n")
		}
		for _, t := range m.Texts {
			fmt.Fprintf(&b, "\n--- %s ---\n\n%s\n", t.Name, t.Text)
		}
	}
	return b.Bytes(), nil
}

func main() {
	check := flag.Bool("check", false, "fail if the notices file is out of date instead of writing it")
	flag.Parse()
	want, err := build()
	if err != nil {
		fmt.Fprintln(os.Stderr, "notices:", err)
		os.Exit(1)
	}
	if *check {
		have, err := os.ReadFile(output)
		if err != nil || !bytes.Equal(have, want) {
			fmt.Fprintf(os.Stderr, "notices: %s is out of date; run: go run ./scripts/notices\n", output)
			os.Exit(1)
		}
		fmt.Printf("ok: %s is current\n", output)
		return
	}
	if err := os.WriteFile(output, want, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "notices:", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s (%d bytes)\n", output, len(want))
}
