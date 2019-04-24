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
	Timestamp uint64    // Monotonic timestamp
	CPU       uint64    // CPU index
	Pid       uint64    // Process ID, who triggered the event
	Typ       uint64    // Event type: enter=0, exit=1
	ID        uint64    // Syscall NR
	Comm      string    // The process command (as in /proc/$pid/comm)
	Args      [6]uint64 // Syscall args
	Ret       uint64    // Return value
	Param     string    // One string parameter
}

func eventToGo(data *[]byte) (ret Event) {
	eventC := (*C.struct_syscall_event_t)(unsafe.Pointer(&(*data)[0]))

	ret.Timestamp = uint64(eventC.timestamp)
	ret.Typ = uint64(eventC.typ)

	switch ret.Typ {
	case 2: // SYSCALL_EVENT_TYPE_CONT
		eventContC := (*C.struct_syscall_event_cont_t)(unsafe.Pointer(&(*data)[0]))
		ret.Param = C.GoString(&eventContC.param[0])

	default: // SYSCALL_EVENT_TYPE_ENTER / SYSCALL_EVENT_TYPE_EXIT
		ret.CPU = uint64(eventC.cpu)
		ret.Pid = uint64(eventC.pid & 0xffffffff)
		ret.ID = uint64(eventC.id)
		ret.Comm = C.GoString(&eventC.comm[0])
		for i := 0; i < 6; i++ {
			ret.Args[i] = uint64(eventC.args[i])
		}
		ret.Ret = uint64(eventC.ret)
	}
	return
}

func eventTimestamp(data *[]byte) uint64 {
	eventC := (*C.struct_syscall_event_t)(unsafe.Pointer(&(*data)[0]))
	return uint64(eventC.timestamp)
}

func (e Event) String() string {
	switch e.Typ {
	case 0:
		return fmt.Sprintf("%v cpu#%d pid %d [%s] %s...", e.Timestamp, e.CPU, e.Pid, e.Comm, syscallGetCall(int(e.ID), e.Args))
	case 1:
		return fmt.Sprintf("%v cpu#%d pid %d [%s] ...%s() returns %d", e.Timestamp, e.CPU, e.Pid, e.Comm, syscallGetName(int(e.ID)), int(e.Ret))
	case 2:
		return fmt.Sprintf("%v %q", e.Timestamp, e.Param)
	default:
		return fmt.Sprintf("%v cpu#%d pid %d [%s] unknown", e.Timestamp, e.CPU, e.Pid, e.Comm)
	}
}
