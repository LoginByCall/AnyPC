package agent

import "sync"

// ClipMax — предел текста буфера обмена за одно сообщение канала данных.
// ponytail: одно сообщение SCTP (64 КБ); до 1 МБ по REQ-F-11 — нарезка на части, когда понадобится.
const ClipMax = 60 << 10

// clipSync защищает от эха: текст, полученный с другой стороны, обратно не отправляется.
type clipSync struct {
	mu   sync.Mutex
	last string
}

// fromRemote — пришло с другой стороны; true — записать в локальный буфер.
func (c *clipSync) fromRemote(text string) bool {
	if text == "" || len(text) > ClipMax {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.last = text
	return true
}

// toRemote — локальный буфер изменился; true — отправить на другую сторону.
func (c *clipSync) toRemote(text string) bool {
	if text == "" || len(text) > ClipMax {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if text == c.last {
		return false
	}
	c.last = text
	return true
}
