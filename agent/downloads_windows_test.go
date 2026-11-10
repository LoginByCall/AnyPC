package agent

import (
	"os"
	"testing"
)

// TestDownloadsDir — Windows отдаёт существующую папку «Загрузки» (на windows-latest — C:\Users\runneradmin\Downloads).
func TestDownloadsDir(t *testing.T) {
	d := DownloadsDir()
	if st, err := os.Stat(d); err != nil || !st.IsDir() {
		t.Fatalf("%q: %v", d, err)
	}
}
