// Command license-admin is a CLI for managing license codes on a running
// license-server via its admin API. The admin token is read from
// LICENSE_ADMIN_TOKEN or -token.
//
// Examples:
//
//	license-admin -server http://localhost:8080 issue -plan pro -features scan,active_scan,cameras -max-devices 3
//	license-admin issue -plan business -features all -expires-days 365
//	license-admin list
//	license-admin revoke AB7K-9QF2-M4TX
//	license-admin enable AB7K-9QF2-M4TX
//	license-admin delete AB7K-9QF2-M4TX
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"spycam-tray-agent/internal/license"
)

func main() {
	server := flag.String("server", envOr("LICENSE_SERVER", "http://localhost:8080"), "license server base URL")
	token := flag.String("token", os.Getenv("LICENSE_ADMIN_TOKEN"), "admin token (or LICENSE_ADMIN_TOKEN env)")
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}
	if *token == "" {
		fatal("no admin token set (use -token or LICENSE_ADMIN_TOKEN)")
	}

	c := license.AdminClient{ServerURL: *server, Token: *token}
	switch args[0] {
	case "issue":
		cmdIssue(c, args[1:])
	case "list":
		cmdList(c)
	case "revoke":
		requireCode(args, func(code string) error { return c.Revoke(code) }, "revoked")
	case "enable":
		requireCode(args, func(code string) error { return c.Enable(code) }, "enabled")
	case "delete":
		requireCode(args, func(code string) error { return c.Delete(code) }, "deleted")
	default:
		usage()
		os.Exit(2)
	}
}

func cmdIssue(c license.AdminClient, argv []string) {
	fs := flag.NewFlagSet("issue", flag.ExitOnError)
	plan := fs.String("plan", "", "plan name (e.g. pro, business)")
	features := fs.String("features", "", "comma-separated features, or 'all'")
	maxDevices := fs.Int("max-devices", 0, "device seat limit (0 = unlimited)")
	expiresDays := fs.Int("expires-days", 0, "days until expiry (0 = never)")
	code := fs.String("code", "", "specific code to create (default: random)")
	_ = fs.Parse(argv)

	var feats []string
	if strings.TrimSpace(*features) == "all" {
		feats = license.AllFeatures()
	} else {
		for _, f := range strings.Split(*features, ",") {
			if f = strings.TrimSpace(f); f != "" {
				feats = append(feats, f)
			}
		}
	}

	al, err := c.Issue(license.IssueRequest{
		Code: *code, Plan: *plan, Features: feats,
		MaxDevices: *maxDevices, ExpiresDays: *expiresDays,
	})
	if err != nil {
		fatal(err.Error())
	}
	fmt.Printf("issued code: %s\n  plan: %s\n  features: %s\n", al.Code, al.Plan, strings.Join(al.Features, ", "))
	if al.MaxDevices > 0 {
		fmt.Printf("  max devices: %d\n", al.MaxDevices)
	}
	if !al.Expires.IsZero() {
		fmt.Printf("  expires: %s\n", al.Expires.Format(time.RFC3339))
	}
}

func cmdList(c license.AdminClient) {
	list, err := c.List()
	if err != nil {
		fatal(err.Error())
	}
	if len(list) == 0 {
		fmt.Println("(no licenses)")
		return
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "CODE\tPLAN\tFEATURES\tDEVICES\tEXPIRES\tSTATUS")
	for _, l := range list {
		exp := "never"
		if !l.Expires.IsZero() {
			exp = l.Expires.Format("2006-01-02")
		}
		seats := fmt.Sprintf("%d", len(l.Devices))
		if l.MaxDevices > 0 {
			seats = fmt.Sprintf("%d/%d", len(l.Devices), l.MaxDevices)
		}
		status := "active"
		if l.Disabled {
			status = "disabled"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", l.Code, l.Plan, strings.Join(l.Features, ","), seats, exp, status)
	}
	_ = tw.Flush()
}

func requireCode(args []string, fn func(string) error, verb string) {
	if len(args) < 2 {
		fatal("usage: " + args[0] + " <CODE>")
	}
	code := args[1]
	if err := fn(code); err != nil {
		fatal(err.Error())
	}
	fmt.Printf("%s: %s\n", verb, code)
}

func usage() {
	fmt.Fprintln(os.Stderr, `license-admin — manage license codes

Usage:
  license-admin [-server URL] [-token TOKEN] <command> [args]

Commands:
  issue   -plan P -features a,b,c [-max-devices N] [-expires-days D] [-code C]
  list
  revoke  <CODE>
  enable  <CODE>
  delete  <CODE>

Env: LICENSE_SERVER, LICENSE_ADMIN_TOKEN`)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "error: "+msg)
	os.Exit(1)
}
