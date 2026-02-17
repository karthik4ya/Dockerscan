package main

import (
	"fmt"
	"os"

	"github.com/cr0hn/dockerscan/v2/internal/offensive"
)

// handleModifyCommand is called from main.go when the user runs the
// `modify` command. It parses CLI flags using the existing helpers
// in main.go and calls the offensive trojanization routine.
func handleModifyCommand() {
	imageName := getImageName()
	if imageName == "" {
		fmt.Fprintln(os.Stderr, "Error: no image specified for modify")
		os.Exit(1)
	}

	lhost := getFlagValue("--lhost")
	if lhost == "" {
		lhost = getFlagValue("-l")
	}

	lport := getFlagValue("--lport")
	if lport == "" {
		lport = getFlagValue("-p")
	}
	if lport == "" {
		lport = "4444"
	}

	output := getFlagValue("--output")
	if output == "" {
		output = getFlagValue("-o")
	}
	if output == "" {
		output = "trojan.tar"
	}

	platform := getFlagValue("--platform")

	if err := offensive.TrojanizeImage(imageName, lhost, lport, output, platform); err != nil {
		fmt.Fprintf(os.Stderr, "Error trojanizing image: %v\n", err)
		os.Exit(1)
	}
}
