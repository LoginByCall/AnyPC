//go:build linux || darwin

package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"anypc/totp"
)

// Ключи настройки без окна — для ПК, где некому открыть интерфейс (сервер, удалённая установка по ssh).
// Каждый меняет настройки и выходит; уже запущенный AnyPC подхватит их после перезапуска.
var (
	cliConfirm   = flag.String("confirm", "", "окно «Разрешить» перед каждым входом по паролю: on или off; и выйти.\noff — только со вторым фактором: QR и ключ TOTP в терминале, код из приложения — со stdin; on — TOTP отключается")
	cliView      = flag.String("view-only", "", "«Только показ экрана»: каждая входящая сессия — только просмотр: on или off; и выйти")
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
		if *cliConfirm == "off" {
			if err := otpSetup(cfg, os.Stdin); err != nil {
				return true, err
			}
		} else if err := cfg.setConfirm(true); err != nil {
			return true, err
		}
		fmt.Println("окно «Разрешить»:", *cliConfirm, map[bool]string{true: "(второй фактор TOTP отключён)", false: "(второй фактор TOTP включён)"}[*cliConfirm == "on"], restartHint)
	case *cliView != "":
		if *cliView != "on" && *cliView != "off" {
			return true, errors.New("--view-only: on или off")
		}
		if err := cfg.setViewOnly(*cliView == "on"); err != nil {
			return true, err
		}
		fmt.Println("только показ экрана:", *cliView, restartHint)
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
		fmt.Printf("AnyPC %s\nID: %s\nКлюч хоста: %s\nПароль задан: %s\nОкно «Разрешить»: %s\nВторой фактор (TOTP): %s\nТолько показ экрана: %s\nУзел: %s (хабы AnyPC запасными: %s)\nАвтозапуск: %s\n",
			version, cfg.ID, cfg.fingerprint(), yesNo(cfg.hasPass()), onOff(cfg.confirm() || !cfg.otpSet()), yesNo(cfg.otpSet()), onOff(cfg.viewOnly()), node, yesNo(public), serviceState())
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

// otpSetup — настройка TOTP в терминале: otpauth-URI и QR полублоками, код со stdin (первая строка).
// Без верного кода вход без подтверждения не включается.
func otpSetup(cfg *config, in io.Reader) error {
	sec := totp.NewSecret()
	u := totp.URI(cfg.ID, sec)
	q, err := totp.Terminal(u)
	if err != nil {
		return err
	}
	fmt.Printf("Вход без подтверждения — только со вторым фактором (TOTP). Отсканируйте QR приложением-аутентификатором\n"+
		"(Google Authenticator, Aegis…) или введите ключ вручную.\n\n%s\n%s\nКлюч: %s\n\nКод из приложения (6 цифр): ", q, u, sec)
	line, _ := bufio.NewReader(in).ReadString('\n')
	if err := cfg.otpEnable(sec, strings.TrimSpace(line)); err != nil {
		if errors.Is(err, errBadCode) {
			return errors.New("код неверный — вход без подтверждения не включён (проверьте время на телефоне и повторите)")
		}
		return err
	}
	return nil
}

const restartHint = "(если AnyPC запущен — перезапустите его)"

func yesNo(b bool) string { return map[bool]string{true: "да", false: "нет"}[b] }
func onOff(b bool) string { return map[bool]string{true: "on", false: "off"}[b] }
