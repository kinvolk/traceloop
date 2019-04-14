package straceback

import (
	"fmt"
	"unsafe"
)

/*
#include "../../bpf/straceback-tailcall-bpf.h"
*/
import "C"

type Event struct {
	Timestamp uint64 // Monotonic timestamp
	CPU       uint64 // CPU index
	Pid       uint64 // Process ID, who triggered the event
	ID        uint64 // Syscall NR
	Comm      string // The process command (as in /proc/$pid/comm)
}

func eventToGo(data *[]byte) (ret Event) {
	eventC := (*C.struct_syscall_event_t)(unsafe.Pointer(&(*data)[0]))

	ret.Timestamp = uint64(eventC.timestamp)
	ret.CPU = uint64(eventC.cpu)
	ret.Pid = uint64(eventC.pid & 0xffffffff)
	ret.ID = uint64(eventC.id)
	ret.Comm = C.GoString(&eventC.comm[0])

	return
}

func eventTimestamp(data *[]byte) uint64 {
	eventC := (*C.struct_syscall_event_t)(unsafe.Pointer(&(*data)[0]))
	return uint64(eventC.timestamp)
}

func (e Event) String() string {
	return fmt.Sprintf("%v cpu#%d pid %d [%s] %s", e.Timestamp, e.CPU, e.Pid, e.Comm, syscallGetCall(int(e.ID)))
}
