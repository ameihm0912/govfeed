// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package govfeed

import (
	"errors"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

type gvCtx struct {
	initialized bool
	vfeed       string
}

const (
	_ = iota
	TOK_CVE_DESCRIPTION
	TOK_CVSS_BASE
)

type parserEntry struct {
	regex string
	token int
}

var parserTable = []parserEntry{
	{"^\\[cve_description\\]:", TOK_CVE_DESCRIPTION},
	{"^\\[cvss_base\\]:", TOK_CVSS_BASE},
}

var ctx gvCtx

func vfRunner(args []string) ([]string, error) {
	var err error
	cmd := exec.Command(ctx.vfeed, args...)
	buf, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	ret := strings.Split(string(buf), "\n")
	return ret, nil
}

func lineParser(ln string) (int, string, error) {
	var rettok int
	found := false
	for _, x := range parserTable {
		flag, err := regexp.MatchString(x.regex, ln)
		if err != nil {
			return 0, "", err
		}
		if flag {
			found = true
			rettok = x.token
			break
		}
	}
	if !found {
		return 0, "", nil
	}
	args := strings.Split(ln, " ")
	if len(args) < 2 {
		return 0, "", nil
	}
	ret := strings.Join(args[1:], " ")
	return rettok, ret, nil
}

func processLine(tok int, buf string, cve *GVCVE) error {
	var err error

	switch tok {
	case TOK_CVE_DESCRIPTION:
		cve.Description = buf
	case TOK_CVSS_BASE:
		cve.CVSS, err = strconv.ParseFloat(buf, 64)
		if err != nil {
			return err
		}
	}
	return nil
}

func GVQuery(cve string) (ret GVCVE, err error) {
	ret.CVEID = cve

	if !ctx.initialized {
		return ret, errors.New("call GVInit() first")
	}

	args := make([]string, 0)
	args = append(args, "get_cve", cve)
	lns, err := vfRunner(args)
	if err != nil {
		return ret, err
	}
	for _, x := range lns {
		tok, buf, err := lineParser(x)
		if err != nil {
			return ret, err
		}
		if len(buf) == 0 {
			continue
		}
		err = processLine(tok, buf, &ret)
		if err != nil {
			return ret, err
		}
	}

	args = nil
	args = make([]string, 0)
	args = append(args, "get_cvss", cve)
	lns, err = vfRunner(args)
	if err != nil {
		return ret, err
	}
	for _, x := range lns {
		tok, buf, err := lineParser(x)
		if err != nil {
			return ret, err
		}
		if len(buf) == 0 {
			continue
		}
		err = processLine(tok, buf, &ret)
		if err != nil {
			return ret, err
		}
	}

	return ret, nil
}

func GVInit(path string) (err error) {
	ctx.initialized = false
	ctx.vfeed = path

	_, err = os.Stat(ctx.vfeed)
	if err != nil {
		return err
	}

	ctx.initialized = true
	return
}
