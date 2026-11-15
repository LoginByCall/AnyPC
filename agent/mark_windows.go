package agent

import (
	"log"
	"os"
)

// markForeign — файл от чужого ПК (Ч10.1, M8 приёмки): Zone.Identifier с ZoneId=3 («из интернета») — SmartScreen и
// Office спросят перед запуском и откроют в защищённом режиме. NTFS ADS; на FAT/exFAT потока нет — пропуск.
func markForeign(path string) {
	if err := os.WriteFile(path+":Zone.Identifier", []byte("[ZoneTransfer]\r\nZoneId=3\r\n"), 0o644); err != nil {
		log.Printf("приём: метка происхождения не поставлена: %v", err)
	}
}
