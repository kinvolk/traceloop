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
	// On Linux 5.5.5-200.fc31.x86_64, I have the following offsets: 2784 8 432
	thresholdNSProxy = 3500
	thresholdUTSNS   = 40
	thresholdIno     = 500
)

// These constants should be in sync with the equivalent definitions in the ebpf program.
const (
	stateUninitialized C.__u64 = 0
	stateChecking      C.__u64 = 1 // status set by userspace, waiting for eBPF
	stateChecked       C.__u64 = 2 // status set by eBPF, waiting for userspace
	stateReady         C.__u64 = 3 // fully initialized, all offset known
)

var stateString = map[C.__u64]string{
	stateUninitialized: "uninitialized",
	stateChecking:      "checking",
	stateChecked:       "checked",
	stateReady:         "ready",
}

var (
	OffsetNsproxy uint64
	OffsetUtsns   uint64
	OffsetIno     uint64
)

// These constants should be in sync with the equivalent definitions in the ebpf program.
const (
	guessUtsns C.__u64 = 0
)

var whatString = map[C.__u64]string{
	guessUtsns: "uts namespace",
}

type fieldValues struct {
	utsns uint32
}

var zero uint64

func ownUtsNS() (uint64, error) {
	var s syscall.Stat_t
	if err := syscall.Stat("/proc/self/ns/uts", &s); err != nil {
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
	case guessUtsns:
		if status.utsns == C.__u32(expected.utsns) {
			status.state = stateReady
		} else {
			// offset_nsproxy -> offset_utsns -> offset_ino
			if status.err == 0 {
				status.offset_ino++
			}
			if status.err == 1 || status.offset_ino >= thresholdIno {
				status.offset_utsns++
				status.offset_ino = 0
			}
			if status.err == 2 || status.offset_utsns >= thresholdUTSNS {
				status.offset_nsproxy++
				status.offset_utsns = 0
				status.offset_ino = 0
			}
			if status.offset_ino >= thresholdIno {
				status.offset_ino = 0
				status.offset_utsns++
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
	currentUtsns, err := ownUtsNS()
	if err != nil {
		return fmt.Errorf("error getting current utsns: %v", err)
	}

	mp := m.Map("guess_status")
	// pid & tid must not change during the guessing work: the communication
	// between ebpf and userspace relies on it
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	pidTgid := uint64(os.Getpid())<<32 | uint64(syscall.Gettid())
	fmt.Printf("pid %v tid %v\n", os.Getpid(), syscall.Gettid())

	status := &guessStatus{
		state:          stateChecking,
		pid_tgid:       C.__u64(pidTgid),
		offset_nsproxy: 1500,
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
		utsns: uint32(currentUtsns),
	}

	for status.state != stateReady {
		//fmt.Printf("Trying %+v expected %+v\n", status, expected)

		if err := tryCurrentOffset(m, mp, status, expected); err != nil {
			return err
		}

		if err := checkAndUpdateCurrentOffset(m, mp, status, expected); err != nil {
			return err
		}

		// Stop at a reasonable offset so we don't run forever.
		// Reading too far away in kernel memory is not a big deal:
		// probe_kernel_read() handles faults gracefully.
		if status.offset_nsproxy >= thresholdNSProxy ||
			status.offset_utsns >= thresholdUTSNS ||
			status.offset_ino >= thresholdIno {
			return fmt.Errorf("overflow while guessing %v, bailing out", whatString[status.what])
		}
	}

	err = m.LookupElement(mp, unsafe.Pointer(&zero), unsafe.Pointer(status))
	if err == nil && status.state == stateReady {
		OffsetNsproxy = uint64(status.offset_nsproxy)
		OffsetUtsns = uint64(status.offset_utsns)
		OffsetIno = uint64(status.offset_ino)
		fmt.Printf("offsets: %v %v %v\n", OffsetNsproxy, OffsetUtsns, OffsetIno)
	}

	return nil
}
