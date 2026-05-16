//go:build !windows

package fim

import (
	"os"
	"syscall"
)

func fileOwner(info os.FileInfo) (uid, gid uint32) {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return stat.Uid, stat.Gid
	}
	return 0, 0
}
