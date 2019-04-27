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
	Typ       int       // Event type: enter=0, exit=1
	ContNr    int       // How many continuation messages after
	CPU       int       // CPU index
	Pid       uint64    // Process ID, who triggered the event
	ID        int       // Syscall NR
	Comm      string    // The process command (as in /proc/$pid/comm)
	Args      [6]uint64 // Syscall args
	Ret       uint64    // Return value
	Param     string    // One string parameter
	ParamIdx  int       // Parameter index
}

func eventToGo(data *[]byte) (ret Event) {
	if len(*data) < 16 {
		return
	}

	eventC := (*C.struct_syscall_event_t)(unsafe.Pointer(&(*data)[0]))

	ret.Timestamp = uint64(eventC.timestamp)
	ret.Typ = int(eventC.typ)

	switch ret.Typ {
	case 2: // SYSCALL_EVENT_TYPE_CONT
		eventContC := (*C.struct_syscall_event_cont_t)(unsafe.Pointer(&(*data)[0]))
		ret.ParamIdx = int(eventContC.index)
		ret.Param = C.GoString(&eventContC.param[0])

	default: // SYSCALL_EVENT_TYPE_ENTER / SYSCALL_EVENT_TYPE_EXIT
		ret.ContNr = int(eventC.cont_nr)
		ret.CPU = int(eventC.cpu)
		ret.Pid = uint64(eventC.pid & 0xffffffff)
		ret.ID = int(eventC.id)
		ret.Comm = C.GoString(&eventC.comm[0])
		if ret.Typ == 0 { // SYSCALL_EVENT_TYPE_ENTER
			for i := 0; i < 6; i++ {
				ret.Args[i] = uint64(eventC.args[i])
			}
		} else { // SYSCALL_EVENT_TYPE_EXIT
			ret.Ret = uint64(eventC.args[0])
		}
	}
	return
}

func eventsToGo(data [][]byte) (ret []Event) {
	for _, d := range data {
		ret = append(ret, eventToGo(&d))
	}
	return
}

func eventTimestamp(data *[]byte) uint64 {
	eventC := (*C.struct_syscall_event_t)(unsafe.Pointer(&(*data)[0]))
	eventContC := (*C.struct_syscall_event_cont_t)(unsafe.Pointer(&(*data)[0]))
	ts := uint64(eventC.timestamp)
	if eventC.typ == 2 {
		// FIXME: quick hack to sort events...
		ts += uint64(eventContC.index) + 1
	}

	return ts
}

func (e Event) String() string {
	switch e.Typ {
	case 0:
		return fmt.Sprintf("%v cpu#%d pid %d [%s] %s...", e.Timestamp, e.CPU, e.Pid, e.Comm, syscallGetCall(int(e.ID), e.Args, nil))
	case 1:
		return fmt.Sprintf("%v cpu#%d pid %d [%s] ...%s() returns %d", e.Timestamp, e.CPU, e.Pid, e.Comm, syscallGetName(int(e.ID)), int(e.Ret))
	case 2:
		return fmt.Sprintf("%v %q", e.Timestamp, e.Param)
	default:
		return fmt.Sprintf("%v cpu#%d pid %d [%s] unknown", e.Timestamp, e.CPU, e.Pid, e.Comm)
	}
}
func eventsToString(events []Event) (ret string) {
	for i := 0; i < len(events); i++ {
		e := events[i]
		switch e.Typ {
		case 0:
			var argsStr [6]*string
			if e.Typ == 0 && i+e.ContNr < len(events) {
				for j := 0; j < e.ContNr; j++ {
					param := events[i+1+j].Param
					paramIdx := events[i+1+j].ParamIdx
					argsStr[paramIdx] = &param
				}
				i += e.ContNr
			}
			returnedValue := "..."
			if e.Typ == 0 && i+1 < len(events) {
				nextE := events[i+1]
				if nextE.Typ == 1 && e.Pid == nextE.Pid && e.ID == nextE.ID {
					returnedValue = fmt.Sprintf(" = %d", nextE.Ret)
					i++
				}
			}
			ret += fmt.Sprintf("%v cpu#%d pid %d [%s] %s%s\n",
				e.Timestamp, e.CPU, e.Pid, e.Comm,
				syscallGetCall(int(e.ID), e.Args, &argsStr),
				returnedValue)
		case 1:
			ret += fmt.Sprintf("%v cpu#%d pid %d [%s] ...%s() = %d\n", e.Timestamp, e.CPU, e.Pid, e.Comm, syscallGetName(int(e.ID)), int(e.Ret))
		case 2:
			ret += fmt.Sprintf("%v %q\n", e.Timestamp, e.Param)
		default:
			ret += fmt.Sprintf("%v cpu#%d pid %d [%s] unknown (#%d)\n", e.Timestamp, e.CPU, e.Pid, e.Comm, e.Typ)
		}
	}
	return
}
