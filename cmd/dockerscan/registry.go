package main

import (
    "fmt"
    "os"

    "github.com/cr0hn/dockerscan/v2/internal/offensive"
)

// handleRegistryCommand is called from main.go when the user runs the
// `registry` command. It reads the target URL from the CLI and invokes
// the offensive registry audit routine.
func handleRegistryCommand() {
    if len(os.Args) < 3 {
        fmt.Fprintln(os.Stderr, "Error: registry command requires a URL argument")
        os.Exit(1)
    }
    url := os.Args[2]
    offensive.ExploitRegistry(url)
}