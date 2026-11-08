//go:build unix

package agent

import "syscall"

// diskFree — сколько байт в dir доступно непривилегированному процессу.
func diskFree(dir string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return uint64(st.Bavail) * uint64(st.Bsize), nil
}
