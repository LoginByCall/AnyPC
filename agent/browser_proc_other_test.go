//go:build !linux

package agent

import "os/exec"

func setChromeProcAttr(cmd *exec.Cmd) {}

func killChrome(cmd *exec.Cmd) {
	if cmd.Process != nil {
		cmd.Process.Kill()
	}
}
