// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package main

import (
	"fmt"
	"govfeed"
	"os"
)

var testcve string = "CVE-2015-2942"

func usage() {
	fmt.Fprint(os.Stderr, "usage: govfeed-test vfeedpath\n")
	os.Exit(1)
}

func main() {
	if len(os.Args) != 2 {
		usage()
	}
	path := os.Args[1]

	err := govfeed.GVInit(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	ret, err := govfeed.GVQuery(testcve)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stdout, "CVE: %v\n", ret.CVEID)
	fmt.Fprintf(os.Stdout, "Description: %v\n", ret.Description)
	fmt.Fprintf(os.Stdout, "CVSS: %v\n", ret.CVSS)
}
