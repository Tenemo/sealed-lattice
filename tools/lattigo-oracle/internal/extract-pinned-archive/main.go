package main

import (
	"archive/zip"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	archivePath := flag.String("archive", "", "pinned Lattigo archive path")
	destinationPath := flag.String("destination", "", "archive extraction destination")
	topLevelDirectory := flag.String("top-level", "", "expected archive top-level directory")
	flag.Parse()

	if *archivePath == "" || *destinationPath == "" || *topLevelDirectory == "" {
		exitWithError("archive, destination, and top-level are required")
	}
	if err := extractArchive(*archivePath, *destinationPath, *topLevelDirectory); err != nil {
		exitWithError(err.Error())
	}
}

func exitWithError(message string) {
	_, _ = fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}

func extractArchive(archivePath, destinationPath, topLevelDirectory string) error {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return fmt.Errorf("open pinned archive: %w", err)
	}
	defer func() {
		_ = reader.Close()
	}()

	cleanDestinationPath, err := filepath.Abs(destinationPath)
	if err != nil {
		return fmt.Errorf("resolve destination path: %w", err)
	}
	expectedPrefix := strings.TrimSuffix(topLevelDirectory, "/") + "/"
	if err := os.MkdirAll(cleanDestinationPath, 0o755); err != nil {
		return fmt.Errorf("create destination directory: %w", err)
	}

	for _, archiveFile := range reader.File {
		if !strings.HasPrefix(archiveFile.Name, expectedPrefix) {
			return fmt.Errorf("archive entry %q is outside %q", archiveFile.Name, topLevelDirectory)
		}
		relativePath := strings.TrimPrefix(archiveFile.Name, expectedPrefix)
		if relativePath == "" {
			continue
		}
		cleanRelativePath := filepath.Clean(relativePath)
		if cleanRelativePath == "." || strings.HasPrefix(cleanRelativePath, ".."+string(os.PathSeparator)) || cleanRelativePath == ".." {
			return fmt.Errorf("archive entry %q resolves outside the destination", archiveFile.Name)
		}
		mode := archiveFile.FileInfo().Mode()
		if mode&os.ModeSymlink != 0 {
			return fmt.Errorf("archive entry %q is a symlink", archiveFile.Name)
		}

		targetPath := filepath.Join(cleanDestinationPath, cleanRelativePath)
		if !strings.HasPrefix(targetPath, cleanDestinationPath+string(os.PathSeparator)) && targetPath != cleanDestinationPath {
			return fmt.Errorf("archive entry %q escapes the destination", archiveFile.Name)
		}
		if archiveFile.FileInfo().IsDir() {
			if err := os.MkdirAll(targetPath, 0o755); err != nil {
				return fmt.Errorf("create archive directory %q: %w", archiveFile.Name, err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
			return fmt.Errorf("create parent directory for %q: %w", archiveFile.Name, err)
		}
		if err := extractFile(archiveFile, targetPath, mode); err != nil {
			return err
		}
	}

	return nil
}

func extractFile(archiveFile *zip.File, targetPath string, mode os.FileMode) error {
	source, err := archiveFile.Open()
	if err != nil {
		return fmt.Errorf("open archive entry %q: %w", archiveFile.Name, err)
	}
	defer func() {
		_ = source.Close()
	}()

	target, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode.Perm())
	if err != nil {
		return fmt.Errorf("create archive entry %q: %w", archiveFile.Name, err)
	}
	defer func() {
		_ = target.Close()
	}()
	if _, err := io.Copy(target, source); err != nil {
		return fmt.Errorf("copy archive entry %q: %w", archiveFile.Name, err)
	}

	return nil
}
