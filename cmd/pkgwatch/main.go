package main

import (
	"os"

	"github.com/myselfvivek17/pkgwatch/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
