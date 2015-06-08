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

	// Try calling without initializing first, make sure we get an
	// error.
	_, err := govfeed.GVQuery(testcve)
	if err == nil {
		fmt.Fprintf(os.Stderr, "error: query should have failed but did not\n")
		os.Exit(1)
	} else {
		fmt.Fprintf(os.Stdout, "uninitialized query failed properly, %v\n", err)
	}

	err = govfeed.GVInit(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stdout, "Trying valid query\n")
	ret, err := govfeed.GVQuery(testcve)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stdout, "CVE: %v\n", ret.CVEID)
	fmt.Fprintf(os.Stdout, "Description: %v\n", ret.Description)
	fmt.Fprintf(os.Stdout, "CVSS: %v\n", ret.CVSS)

	fmt.Fprintf(os.Stdout, "Trying invalid query\n")
	ret, err = govfeed.GVQuery("INVALID")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stdout, "CVE: %v\n", ret.CVEID)
	if len(ret.Description) == 0 {
		fmt.Fprintf(os.Stdout, "Description correctly zero length\n")
	} else {
		fmt.Fprintf(os.Stdout, "Description should have been empty but was not, %v\n", ret.Description)
	}
}
