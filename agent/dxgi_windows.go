package agent

import (
	"strings"
	"syscall"
	"unsafe"
)

// monitors — выходы DXGI адаптера 0 в порядке EnumOutputs: это те же номера, что у ddagrab output_idx.
// ponytail: только адаптер 0 — мониторы на втором GPU (ноутбуки с дискретной картой) не видны; ddagrab их тоже не берёт.
var (
	pCreateDXGIFactory1 = syscall.NewLazyDLL("dxgi.dll").NewProc("CreateDXGIFactory1")
	pGetSystemMetrics   = user32.NewProc("GetSystemMetrics")
	iidDXGIFactory1     = syscall.GUID{Data1: 0x770aae78, Data2: 0xf26f, Data3: 0x4dba, Data4: [8]byte{0xa8, 0x29, 0x25, 0x3c, 0x83, 0xd1, 0xb3, 0x87}}
)

// comCall вызывает метод COM-объекта по номеру в таблице виртуальных методов.
func comCall(obj uintptr, idx int, args ...uintptr) uintptr {
	vtbl := *(*uintptr)(ptr(obj))
	fn := *(*uintptr)(ptr(vtbl + uintptr(idx)*unsafe.Sizeof(uintptr(0))))
	r, _, _ := syscall.SyscallN(fn, append([]uintptr{obj}, args...)...)
	return r
}

type dxgiOutputDesc struct {
	DeviceName [32]uint16
	L, T, R, B int32 // DesktopCoordinates
	Attached   int32
	Rotation   uint32
	Monitor    uintptr
}

func monitors() []Monitor {
	var factory, adapter uintptr
	if r, _, _ := pCreateDXGIFactory1.Call(uintptr(unsafe.Pointer(&iidDXGIFactory1)), uintptr(unsafe.Pointer(&factory))); r != 0 {
		return nil
	}
	defer comCall(factory, 2)                                            // Release
	if comCall(factory, 12, 0, uintptr(unsafe.Pointer(&adapter))) != 0 { // IDXGIFactory1::EnumAdapters1
		return nil
	}
	defer comCall(adapter, 2)
	var out []Monitor
	for i := uintptr(0); ; i++ {
		var output uintptr
		if comCall(adapter, 7, i, uintptr(unsafe.Pointer(&output))) != 0 { // IDXGIAdapter::EnumOutputs; конец — DXGI_ERROR_NOT_FOUND
			break
		}
		var d dxgiOutputDesc
		comCall(output, 7, uintptr(unsafe.Pointer(&d))) // IDXGIOutput::GetDesc
		comCall(output, 2)
		name := strings.TrimPrefix(syscall.UTF16ToString(d.DeviceName[:]), `\\.\`)
		out = append(out, Monitor{Name: name, X: int(d.L), Y: int(d.T), W: int(d.R - d.L), H: int(d.B - d.T), Primary: d.L == 0 && d.T == 0})
	}
	return out
}

// virtualDesk — норма 0..65535 по всему виртуальному экрану для MOUSEEVENTF_VIRTUALDESK.
func virtualDesk(px, py int) (int32, int32) {
	m := func(i uintptr) int { r, _, _ := pGetSystemMetrics.Call(i); return int(int32(r)) }
	vx, vy, vw, vh := m(76), m(77), m(78), m(79) // SM_X/YVIRTUALSCREEN, SM_CX/CYVIRTUALSCREEN
	if vw < 2 || vh < 2 {
		return 0, 0
	}
	return int32((px - vx) * 65535 / (vw - 1)), int32((py - vy) * 65535 / (vh - 1))
}
