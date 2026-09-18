//go:build unix

package cliutil

import (
	"fmt"
	"io/fs"
)

// checkRequestKeyFilePerms rejects a request key file that users other than the owner can read, the same way OpenSSH refuses a world-readable private key
func checkRequestKeyFilePerms(mode fs.FileMode) error {
	if mode.Perm()&0o077 == 0 {
		return nil
	}

	return fmt.Errorf("permissions %#o are too open: the file must not be accessible by group or others (try `chmod 600`)", mode.Perm())
}
