//go:build linux

package agent

import (
	"os/exec"
	"syscall"
)

// Chrome не должен пережить go test, даже если тестовый процесс убили без defer.
func setChromeProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
}

func killChrome(cmd *exec.Cmd) {
	if cmd.Process != nil {
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
