package main

import (
	"os"

	"github.com/italypaleale/revaulter/cmd/cli/cmd"
)

func main() {
	ok := cmd.Run()
	if !ok {
		os.Exit(1)
	}
}
