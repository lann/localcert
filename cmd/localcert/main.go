package main

import (
	"flag"
	"log"

	"github.com/lann/localcert/internal/cli"
)

func main() {
	flag.Parse()

	subcmd := "provision"
	if len(flag.Args()) > 0 {
		subcmd = flag.Args()[0]
	}

	switch subcmd {
	case "provision":
		cli.Provision()
	case "test":
		cli.Test()
	default:
		log.Fatalf("Invalid subcommand %q", subcmd)
	}
}
