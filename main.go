package main

import (
	_ "modernc.org/sqlite"

	"github.com/vincents-ai/transparenz/cmd"
)

func main() {
	cmd.Execute()
}
