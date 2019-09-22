package straceback

import (
	"fmt"
	"time"
	"unsafe"
)

/*
#include "../../bpf/straceback-tailcall-bpf.h"
*/
import "C"

var useNullByteLength uint64 = uint64(C.USE_NULL_BYTE_LENGTH)
var useRetAsParamLength uint64 = uint64(C.USE_RET_AS_PARAM_LENGTH)
var useArgIndexAsParamLength uint64 = uint64(C.USE_ARG_INDEX_AS_PARAM_LENGTH)
var paramProbeAtExitMask uint64 = uint64(C.PARAM_PROBE_AT_EXIT_MASK)

type Event struct {
	Timestamp uint64    // Monotonic timestamp
	Typ       int       // Event type: enter=0, exit=1, cont=2
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
	case 3: // SYSCALL_EVENT_TYPE_LOST
		ret.CPU = int(eventC.cpu)
	case 2: // SYSCALL_EVENT_TYPE_CONT
		eventContC := (*C.struct_syscall_event_cont_t)(unsafe.Pointer(&(*data)[0]))
		ret.ParamIdx = int(eventContC.index)
		if eventContC.failed != 0 {
			ret.Param = "(Pointer deref failed!)"
		} else if uint64(eventContC.length) == useNullByteLength {
		        // 0 byte at [C.PARAM_LENGTH - 1] is enforced in BPF code
			ret.Param = C.GoString(&eventContC.param[0])
		} else {
			ret.Param = C.GoStringN(&eventContC.param[0], C.int(eventContC.length))
		}

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

func MakeLostEventIndicator(cpu uint16, data []byte) ([]byte, error) {
	// This operates on a copy of the original array
	eventC := (*C.struct_syscall_event_t)(unsafe.Pointer(&data[0]))
	// Decrease the timestamp to simulate an older event in the sorting
	eventC.timestamp = eventC.timestamp - 1
	eventC.typ = C.SYSCALL_EVENT_TYPE_LOST
	eventC.cpu = C.ushort(cpu)
	fmt.Printf("Inserted LOST event\n")
	return data, nil
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
	case 3:
		return fmt.Sprintf("%v cpu#%d Previous events might be lost due to full buffer", e.Timestamp, e.CPU)
	default:
		return fmt.Sprintf("%v cpu#%d pid %d [%s] unknown", e.Timestamp, e.CPU, e.Pid, e.Comm)
	}
}
func eventsToString(events []Event) (ret string) {
	for i := 0; i < len(events); i++ {
		e := events[i]
		ts := time.Unix(0, int64(e.Timestamp-events[0].Timestamp))
		timeStr := fmt.Sprintf("%02d:%02d.%09d", ts.Minute(), ts.Second(), ts.Nanosecond())
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
				timeStr, e.CPU, e.Pid, e.Comm,
				syscallGetCall(int(e.ID), e.Args, &argsStr),
				returnedValue)
		case 1:
			ret += fmt.Sprintf("%v cpu#%d pid %d [%s] ...%s() = %d\n", timeStr, e.CPU, e.Pid, e.Comm, syscallGetName(int(e.ID)), int(e.Ret))
		case 2:
			ret += fmt.Sprintf("%v %q\n", timeStr, e.Param)
		case 3:
			ret += fmt.Sprintf("%v cpu#%d Previous events might be lost due to full buffer", e.Timestamp, e.CPU)
		default:
			ret += fmt.Sprintf("%v cpu#%d pid %d [%s] unknown (#%d)\n", timeStr, e.CPU, e.Pid, e.Comm, e.Typ)
		}
	}
	return
}
