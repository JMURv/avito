package db

import (
	"fmt"
	"os"
	"path/filepath"
)

func findRootDir() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		if dir == "/" {
			break
		}
		dir = filepath.Dir(dir)
	}
	return "", fmt.Errorf("go.mod not found")
}
