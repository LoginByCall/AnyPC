package agent

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"time"
)

// markForeign — файл от чужого ПК (Ч10.1, M8 приёмки): com.apple.quarantine — Gatekeeper спросит перед первым
// запуском. Флаги 0081 — «загружено, не проверено», как у браузеров. xattr — по абсолютному пути (PATH не
// подменить), "--" до операндов, не дольше 5 с.
func markForeign(path string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	v := fmt.Sprintf("0081;%x;AnyPC;", time.Now().Unix())
	if out, err := exec.CommandContext(ctx, "/usr/bin/xattr", "-w", "--", "com.apple.quarantine", v, path).CombinedOutput(); err != nil {
		log.Printf("приём: метка происхождения не поставлена: %v %s", err, out)
	}
}
