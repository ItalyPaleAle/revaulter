//go:build unix

package cmd

import "syscall"

// oNoFollow refuses to open the target through a symlink at the kernel level
// This closes the small TOCTOU window between the Lstat pre-check and OpenFile in writeOutputFile
const oNoFollow = syscall.O_NOFOLLOW
