//go:build !unix

package cliutil

import (
	"io/fs"
)

// checkRequestKeyFilePerms is a no-op outside of Unix
// Windows does not map its ACLs onto the Unix mode bits, so the permissions reported by Stat say nothing about who can actually read the file
func checkRequestKeyFilePerms(_ fs.FileMode) error {
	return nil
}
