package agent

import (
	"fmt"
	"log"
	"os/exec"
	"time"
)

// markForeign — файл от чужого ПК (Ч10.1, M8 приёмки): com.apple.quarantine — Gatekeeper спросит перед первым
// запуском. Флаги 0081 — «загружено, не проверено», как у браузеров.
func markForeign(path string) {
	v := fmt.Sprintf("0081;%x;AnyPC;", time.Now().Unix())
	if out, err := exec.Command("xattr", "-w", "com.apple.quarantine", v, path).CombinedOutput(); err != nil {
		log.Printf("приём: метка происхождения не поставлена: %v %s", err, out)
	}
}
