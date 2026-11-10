//go:build linux || darwin

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
)

// Ключи настройки без окна — для ПК, где некому открыть интерфейс (сервер, удалённая установка по ssh).
// Каждый меняет настройки и выходит; уже запущенный AnyPC подхватит их после перезапуска.
var (
	cliConfirm   = flag.String("confirm", "", "окно «Разрешить» перед каждым входом по паролю: on или off; и выйти")
	cliNode      = flag.String("node", "", "свой узел-хаб (например node.example.com), «-» — вернуть хабы AnyPC; и выйти")
	cliPublic    = flag.Bool("node-public", false, "вместе с --node: хабы AnyPC остаются запасными")
	cliStatus    = flag.Bool("status", false, "напечатать настройки и состояние автозапуска и выйти")
	cliInstall   = flag.Bool("install-service", false, "автозапуск при входе в графический сеанс (Linux: systemd --user, macOS: LaunchAgent) и выйти")
	cliUninstall = flag.Bool("uninstall-service", false, "убрать автозапуск и выйти")
)

// runCLI выполняет ключ настройки; done — ключ был, программа должна выйти.
func runCLI(cfg *config) (done bool, err error) {
	switch {
	case *cliConfirm != "":
		if *cliConfirm != "on" && *cliConfirm != "off" {
			return true, errors.New("--confirm: on или off")
		}
		if err := cfg.setConfirm(*cliConfirm == "on"); err != nil {
			return true, err
		}
		fmt.Println("окно «Разрешить»:", *cliConfirm, restartHint)
	case *cliNode != "":
		n := *cliNode
		if n == "-" {
			n = ""
		}
		s, err := applyNode(cfg, n, *cliPublic)
		if err != nil {
			return true, fmt.Errorf("--node: %w", err)
		}
		fmt.Println("сигнализация:", s, restartHint)
	case *cliStatus:
		node, public := cfg.node()
		if node == "" {
			node = "— (хабы AnyPC)"
		}
		fmt.Printf("AnyPC %s\nID: %s\nКлюч хоста: %s\nПароль задан: %s\nОкно «Разрешить»: %s\nУзел: %s (хабы AnyPC запасными: %s)\nАвтозапуск: %s\n",
			version, cfg.ID, cfg.fingerprint(), yesNo(cfg.hasPass()), onOff(cfg.confirm()), node, yesNo(public), serviceState())
	case *cliInstall:
		exe, err := os.Executable()
		if err != nil {
			return true, err
		}
		if err := installService(exe); err != nil {
			return true, fmt.Errorf("автозапуск: %w", err)
		}
		fmt.Printf("автозапуск включён: %s\nПереместите файл — повторите --install-service. %s\n", exe, serviceHint)
	case *cliUninstall:
		if err := uninstallService(); err != nil {
			return true, fmt.Errorf("автозапуск: %w", err)
		}
		fmt.Println("автозапуск убран")
	default:
		return false, nil
	}
	return true, nil
}

const restartHint = "(если AnyPC запущен — перезапустите его)"

func yesNo(b bool) string { return map[bool]string{true: "да", false: "нет"}[b] }
func onOff(b bool) string { return map[bool]string{true: "on", false: "off"}[b] }
