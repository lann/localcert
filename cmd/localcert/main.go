package main

import (
	"flag"
	"log"

	"github.com/lann/localcert/internal/cli"
)

func main() {
	flag.Parse()
	subcmd := flag.Arg(0)
	switch flag.Arg(0) {
	case "provision", "":
		cli.Provision()
	case "test":
		cli.Test()
	default:
		log.Fatalf("Invalid subcommand %q", subcmd)
	}
}
