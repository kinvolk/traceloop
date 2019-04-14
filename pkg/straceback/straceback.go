package straceback

import (
	"bytes"
	"fmt"
	"time"
	"unsafe"

	bpflib "github.com/iovisor/gobpf/elf"
)

/*
#include "../../bpf/straceback-main-bpf.h"

const int MaxTracedPrograms = MAX_TRACED_PROGRAMS;
*/
import "C"

type Tracelet struct {
	tailCallProg *bpflib.Module
	pm           *bpflib.PerfMap
	queueMap     *bpflib.Map
	eventChan    chan []byte
	lostChan     chan uint64
}

type StraceBack struct {
	mainProg    *bpflib.Module
	cgroupMap   *bpflib.Map
	tailCallMap *bpflib.Map
	tracelets   []*Tracelet
	stopChan    chan struct{}
}

func NewTracer() (*StraceBack, error) {
	fmt.Printf("max: %d\n", C.MaxTracedPrograms)
	buf, err := Asset("straceback-main-bpf.o")
	if err != nil {
		return nil, fmt.Errorf("couldn't find asset: %s", err)
	}
	reader := bytes.NewReader(buf)

	m := bpflib.NewModuleFromReader(reader)
	if m == nil {
		return nil, fmt.Errorf("BPF not supported")
	}

	err = m.Load(nil)
	if err != nil {
		return nil, err
	}
	cgroupMap := m.Map("cgroup_map")
	tailCallMap := m.Map("tail_call_map")

	err = m.EnableTracepoint("tracepoint/raw_syscalls/sys_enter")
	if err != nil {
		return nil, err
	}

	stopChan := make(chan struct{})

	return &StraceBack{
		mainProg:    m,
		cgroupMap:   cgroupMap,
		tailCallMap: tailCallMap,
		tracelets:   make([]*Tracelet, C.MaxTracedPrograms),
		stopChan:    stopChan,
	}, nil
}

func (sb *StraceBack) AddProg(cgroupPath string) (uint32, error) {
	cgroupId, err := GetCgroupID(cgroupPath)
	if err != nil {
		return 0, err
	}

	var idx uint32
	for i := 0; i < int(C.MaxTracedPrograms); i++ {
		if sb.tracelets[i] == nil {
			idx = uint32(i)
			break
		}
	}
	if sb.tracelets[idx] != nil {
		return 0, fmt.Errorf("too many traced programs")
	}

	tracelet := Tracelet{}
	tracelet.eventChan = make(chan []byte)
	tracelet.lostChan = make(chan uint64)

	buf, err := Asset("straceback-tailcall-bpf.o")
	if err != nil {
		return 0, fmt.Errorf("couldn't find asset: %s", err)
	}
	reader := bytes.NewReader(buf)

	m := bpflib.NewModuleFromReader(reader)
	if m == nil {
		return 0, fmt.Errorf("BPF not supported")
	}
	tracelet.tailCallProg = m

	sectionParams := make(map[string]bpflib.SectionParams)
	sectionParams["maps/events"] = bpflib.SectionParams{PerfRingBufferPageCount: 4}
	err = m.Load(sectionParams)
	if err != nil {
		return 0, err
	}
	tracelet.queueMap = m.Map("queue")
	pm, err := bpflib.InitPerfMap(m, "events", tracelet.eventChan, tracelet.lostChan)
	if err != nil {
		return 0, fmt.Errorf("error initializing perf map: %v", err)
	}
	tracelet.pm = pm
	sb.tracelets[idx] = &tracelet

	var fd int = -1
	for tp := range m.IterTracepointProgram() {
		fmt.Printf("name: %s\n", tp.Name)
		if tp.Name == "tracepoint/raw_syscalls/sys_enter" {
			fd = tp.Fd()
			break
		}
	}
	if fd == -1 {
		return 0, fmt.Errorf("couldn't find tracepoint fd")
	}
	if err := sb.mainProg.UpdateElement(sb.cgroupMap, unsafe.Pointer(&cgroupId), unsafe.Pointer(&idx), 0); err != nil {
		return 0, fmt.Errorf("error updating tail call map: %v", err)
	}
	if err := sb.mainProg.UpdateElement(sb.tailCallMap, unsafe.Pointer(&idx), unsafe.Pointer(&fd), 0); err != nil {
		return 0, fmt.Errorf("error updating tail call map: %v", err)
	}

	return idx, nil
}

func (sb *StraceBack) DumpProgWithQueue(id uint32) (err error) {
	if id >= uint32(C.MaxTracedPrograms) || sb.tracelets[id] == nil {
		return fmt.Errorf("invalid index")
	}
	if sb.tracelets[id].queueMap == nil {
		return fmt.Errorf("not implemented")
	}

	var value uint64

	for err == nil {
		if err := sb.tracelets[id].tailCallProg.LookupAndDeleteElement(sb.tracelets[id].queueMap, unsafe.Pointer(&value)); err != nil {
			return fmt.Errorf("error reading queue: %v", err)
		}
		fmt.Printf("value: %v(%d)\n", syscallGetName(int(value)), value)
	}
	return nil
}

func (sb *StraceBack) DumpProg(id uint32) (out string, err error) {
	if id >= uint32(C.MaxTracedPrograms) || sb.tracelets[id] == nil {
		return "", fmt.Errorf("invalid index")
	}

	err = sb.tracelets[id].tailCallProg.PerfMapStop("events")
	if err != nil {
		return "", err
	}

	sb.tracelets[id].pm.PollStart()
	for {
		select {
		case <-sb.stopChan:
			// On stop, stopChan will be closed but the other channels will
			// also be closed shortly after. The select{} has no priorities,
			// therefore, the "ok" value must be checked below.
			fmt.Printf("stopChan\n")
			return
		case data, ok := <-sb.tracelets[id].eventChan:
			if !ok {
				fmt.Printf("eventChan not ok\n")
				return // see explanation above
			}
			out += fmt.Sprintf("%s\n", eventToGo(&data).String())
		case lost, ok := <-sb.tracelets[id].lostChan:
			if !ok {
				fmt.Printf("lostChan not ok\n")
				return // see explanation above
			}
			fmt.Printf("lost: %v\n", lost)
		case <-time.After(100 * time.Millisecond):
			return out, nil
		}
	}
	return
}

func (sb *StraceBack) Stop() {
	close(sb.stopChan)
	for i, _ := range sb.tracelets {
		if sb.tracelets[i] != nil {
			sb.tracelets[i].pm.PollStop()
		}
	}
	sb.mainProg.Close()
}
