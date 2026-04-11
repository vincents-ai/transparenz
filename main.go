package main

import (
	_ "modernc.org/sqlite"

	"github.com/shift/transparenz/cmd"
)

func main() {
	cmd.Execute()
}
