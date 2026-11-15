//go:build !windows && !darwin

package agent

// markForeign — на Linux общей метки происхождения файла нет (M8 приёмки): ничего.
func markForeign(string) {}
