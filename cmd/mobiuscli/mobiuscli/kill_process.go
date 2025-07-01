//go:build !windows
// +build !windows

package mobiuscli

import "syscall"

func killPID(pid int) error {
	return syscall.Kill(pid, syscall.SIGKILL)
}
