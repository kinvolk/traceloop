package straceback

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	bpflib "github.com/iovisor/gobpf/elf"
)

/*
#include "../../bpf/straceback-guess-bpf.h"
*/
import "C"

type guessStatus C.struct_guess_status_t

const (
	// When reading kernel structs at different offsets, don't go over that
	// limit. This is an arbitrary choice to avoid infinite loops.
	threshold_nsproxy = 2300 // 1856
	threshold_pidns   = 40   // 32
	threshold_ino     = 230  // 184 + 16
)

// These constants should be in sync with the equivalent definitions in the ebpf program.
const (
	stateUninitialized C.__u64 = 0
	stateChecking              = 1 // status set by userspace, waiting for eBPF
	stateChecked               = 2 // status set by eBPF, waiting for userspace
	stateReady                 = 3 // fully initialized, all offset known
)

var stateString = map[C.__u64]string{
	stateUninitialized: "uninitialized",
	stateChecking:      "checking",
	stateChecked:       "checked",
	stateReady:         "ready",
}

var (
	OffsetNsproxy uint64
	OffsetPidns   uint64
	OffsetIno     uint64
)

// These constants should be in sync with the equivalent definitions in the ebpf program.
const (
	guessPidns C.__u64 = 0
)

var whatString = map[C.__u64]string{
	guessPidns: "pid namespace",
}

type fieldValues struct {
	pidns uint32
}

var zero uint64

func ownPidNS() (uint64, error) {
	var s syscall.Stat_t
	if err := syscall.Stat("/proc/self/ns/pid", &s); err != nil {
		return 0, err
	}
	return s.Ino, nil
}

func tryCurrentOffset(module *bpflib.Module, mp *bpflib.Map, status *guessStatus, expected *fieldValues) error {
	syscall.Access("/", 0)
	return nil
}

func checkAndUpdateCurrentOffset(module *bpflib.Module, mp *bpflib.Map, status *guessStatus, expected *fieldValues) error {
	// get the updated map value so we can check if the current offset is
	// the right one
	if err := module.LookupElement(mp, unsafe.Pointer(&zero), unsafe.Pointer(status)); err != nil {
		return fmt.Errorf("error reading guess_status: %v", err)
	}

	if status.state != stateChecked {
		return fmt.Errorf("invalid guessing state while guessing %v, got %v expected %v",
			whatString[status.what], stateString[status.state], stateString[stateChecked])
	}

	switch status.what {
	case guessPidns:
		if status.pidns == C.__u32(expected.pidns) {
			status.state = stateReady
		} else {
			// offset_nsproxy -> offset_pidns -> offset_ino
			if status.err == 0 {
				status.offset_ino++
			}
			if status.err == 1 || status.offset_ino >= threshold_ino {
				status.offset_pidns++
				status.offset_ino = 0
			}
			if status.err == 2 || status.offset_pidns >= threshold_pidns {
				status.offset_nsproxy++
				status.offset_pidns = 0
				status.offset_ino = 0
			}
			if status.offset_ino >= threshold_ino {
				status.offset_ino = 0
				status.offset_pidns++
			}
			status.state = stateChecking
		}
	default:
		return fmt.Errorf("unexpected field to guess: %v", whatString[status.what])
	}

	// update the map with the new offset/field to check
	if err := module.UpdateElement(mp, unsafe.Pointer(&zero), unsafe.Pointer(status), 0); err != nil {
		return fmt.Errorf("error updating guess_status: %v", err)
	}

	return nil
}

func guess(m *bpflib.Module) error {
	currentPidns, err := ownPidNS()
	if err != nil {
		return fmt.Errorf("error getting current pidns: %v", err)
	}

	mp := m.Map("guess_status")
	// pid & tid must not change during the guessing work: the communication
	// between ebpf and userspace relies on it
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	pidTgid := uint64(os.Getpid())<<32 | uint64(syscall.Gettid())
	fmt.Printf("pid %v tid %v\n", os.Getpid(), syscall.Gettid())

	status := &guessStatus{
		state:    stateChecking,
		pid_tgid: C.__u64(pidTgid),
	}

	// if we already have the offsets, just return
	err = m.LookupElement(mp, unsafe.Pointer(&zero), unsafe.Pointer(status))
	if err == nil && status.state == stateReady {
		return nil
	}

	// initialize map
	if err := m.UpdateElement(mp, unsafe.Pointer(&zero), unsafe.Pointer(status), 0); err != nil {
		return fmt.Errorf("error initializing guess_status map: %v", err)
	}

	expected := &fieldValues{
		pidns: uint32(currentPidns),
	}

	for status.state != stateReady {
		if err := tryCurrentOffset(m, mp, status, expected); err != nil {
			return err
		}

		if err := checkAndUpdateCurrentOffset(m, mp, status, expected); err != nil {
			return err
		}

		// Stop at a reasonable offset so we don't run forever.
		// Reading too far away in kernel memory is not a big deal:
		// probe_kernel_read() handles faults gracefully.
		if status.offset_nsproxy >= threshold_nsproxy ||
			status.offset_pidns >= threshold_pidns ||
			status.offset_ino >= threshold_ino {
			return fmt.Errorf("overflow while guessing %v, bailing out", whatString[status.what])
		}
	}

	err = m.LookupElement(mp, unsafe.Pointer(&zero), unsafe.Pointer(status))
	if err == nil && status.state == stateReady {
		OffsetNsproxy = uint64(status.offset_nsproxy)
		OffsetPidns = uint64(status.offset_pidns)
		OffsetIno = uint64(status.offset_ino)
		fmt.Printf("offsets: %v %v %v\n", OffsetNsproxy, OffsetPidns, OffsetIno)
	}

	return nil
}
