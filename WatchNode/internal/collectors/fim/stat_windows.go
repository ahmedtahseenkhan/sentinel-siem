//go:build windows

package fim

import "os"

func fileOwner(info os.FileInfo) (uid, gid uint32) {
	return 0, 0
}
