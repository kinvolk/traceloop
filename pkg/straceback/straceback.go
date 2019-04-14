package straceback

import (
	"bytes"
	"fmt"
	"time"
	"unsafe"

	bpflib "github.com/iovisor/gobpf/elf"
)

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
	tracelets   map[uint64]Tracelet
	stopChan    chan struct{}
}

func NewTracer() (*StraceBack, error) {
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
		tracelets:   make(map[uint64]Tracelet),
		stopChan:    stopChan,
	}, nil
}

func (sb *StraceBack) AddProg(cgroupPath string, cgroupId uint64) (uint64, error) {
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
	sb.tracelets[cgroupId] = tracelet

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
	var idx uint32
	if err := sb.mainProg.UpdateElement(sb.cgroupMap, unsafe.Pointer(&cgroupId), unsafe.Pointer(&idx), 0); err != nil {
		return 0, fmt.Errorf("error updating tail call map: %v", err)
	}
	if err := sb.mainProg.UpdateElement(sb.tailCallMap, unsafe.Pointer(&idx), unsafe.Pointer(&fd), 0); err != nil {
		return 0, fmt.Errorf("error updating tail call map: %v", err)
	}

	return cgroupId, nil
}

func (sb *StraceBack) DumpProgWithQueue(id uint64) (err error) {
	fmt.Printf("Dump with queue map:\n")
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

func (sb *StraceBack) DumpProg(id uint64) (err error) {
	fmt.Printf("Dump:\n")

	err = sb.tracelets[id].tailCallProg.PerfMapStop("events")
	if err != nil {
		return err
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
			fmt.Printf("%s\n", eventToGo(&data).String())
		case lost, ok := <-sb.tracelets[id].lostChan:
			if !ok {
				fmt.Printf("lostChan not ok\n")
				return // see explanation above
			}
			fmt.Printf("lost: %v\n", lost)
			//default:
			//	fmt.Printf("default\n")
			//	return
		case <-time.After(100 * time.Millisecond):
			return
		}
	}
	return
}

func (sb *StraceBack) Stop() {
	close(sb.stopChan)
	for i, _ := range sb.tracelets {
		sb.tracelets[i].pm.PollStop()
	}
	sb.mainProg.Close()
}
