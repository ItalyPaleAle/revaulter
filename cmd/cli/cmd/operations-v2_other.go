//go:build !unix

package cmd

// oNoFollow is unavailable on non-unix platforms
// On those platforms writeOutputFile relies solely on the Lstat pre-check (small TOCTOU window) to refuse symlinks
const oNoFollow = 0
