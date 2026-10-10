package main

import (
	"strings"
	"testing"
)

func TestClassify(t *testing.T) {
	// The MPL-2.0 text names the GNU licences in its "Secondary License" definition. A classifier
	// that looks for those words first reports every MPL module as AGPL (it did, once).
	mpl := "Mozilla Public License Version 2.0\n==================================\n\n1. Definitions\n" +
		"1.12. \"Secondary License\" means either the GNU General Public License, Version 2.0, the GNU Lesser General Public\n" +
		"License, Version 2.1, the GNU Affero General Public License, Version 3.0, or any later versions of those licenses.\n"
	cases := []struct{ name, text, want string }{
		{"MPL mentioning the GNU licences", mpl, "MPL-2.0"},
		{"hashicorp MPL header", "Copyright (c) 2015 HashiCorp, Inc.\n\nMozilla Public License, version 2.0\n\n1. Definitions\n", "MPL-2.0"},
		{"MIT", "MIT License\n\nCopyright (c) 2020 Someone\n\nPermission is hereby granted, free of charge, to any person obtaining a copy", "MIT"},
		{"Apache", "                                 Apache License\n                           Version 2.0, January 2004\n", "Apache-2.0"},
		{"BSD-3", "Copyright (c) 2009 The Go Authors.\n\nRedistribution and use in source and binary forms, with or without\nmodification, are permitted provided that the following conditions are met:\n\n * Neither the name of Google Inc. nor the names of its contributors may be used to endorse or promote products", "BSD-3-Clause"},
		{"BSD-2", "Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:\n1. Redistributions of source code must retain the above copyright notice.\n2. Redistributions in binary form must reproduce the above copyright notice.", "BSD-2-Clause"},
		{"ISC", "ISC License\n\nCopyright (c) 2004\n\nPermission to use, copy, modify, and/or distribute this software for any purpose", "ISC"},
		{"GPL by title", "                    GNU GENERAL PUBLIC LICENSE\n                       Version 3, 29 June 2007\n", "GPL"},
		{"AGPL by title", "                    GNU AFFERO GENERAL PUBLIC LICENSE\n                       Version 3, 19 November 2007\n", "AGPL"},
		{"LGPL by title", "                  GNU LESSER GENERAL PUBLIC LICENSE\n                       Version 3, 29 June 2007\n", "LGPL"},
		{"unrecognised", "All rights reserved. You may not use this.", "UNKNOWN"},
	}
	for _, c := range cases {
		if got := classify(c.text); got != c.want {
			t.Errorf("%s: classified as %s, want %s", c.name, got, c.want)
		}
	}
}

func TestPolicyRefusesCopyleftAndUnknown(t *testing.T) {
	for _, l := range []string{"GPL", "AGPL", "LGPL", "UNKNOWN", ""} {
		if allowed[l] {
			t.Errorf("%q must not be on the allowlist", l)
		}
	}
	for _, l := range []string{"MIT", "Apache-2.0", "BSD-3-Clause", "BSD-2-Clause", "ISC", "MPL-2.0"} {
		if !allowed[l] {
			t.Errorf("%q should be allowed", l)
		}
	}
	if !strings.HasSuffix(output, "THIRD_PARTY_NOTICES.txt") {
		t.Errorf("unexpected output path %s", output)
	}
}
