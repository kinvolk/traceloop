package straceback

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	bpflib "github.com/iovisor/gobpf/elf"

	"github.com/kinvolk/traceloop/pkg/podinformer"
	"github.com/kinvolk/traceloop/pkg/procinformer"
)

/*
#include "../../bpf/straceback-guess-bpf.h"

const int MaxTracedPrograms = MAX_TRACED_PROGRAMS;
const int MaxPooledPrograms = MAX_POOLED_PROGRAMS;

const unsigned char ContainerEventTypeCreate = CONTAINER_EVENT_TYPE_CREATE;
const unsigned char ContainerEventTypeUpdate = CONTAINER_EVENT_TYPE_UPDATE;
const unsigned char ContainerEventTypeDelete = CONTAINER_EVENT_TYPE_DELETE;

const unsigned int ContainerStatusWaiting = CONTAINER_STATUS_WAITING;
const unsigned int ContainerStatusReady = CONTAINER_STATUS_READY;
*/
import "C"

const maxEvents = 4000

type traceletStatus int

const (
	traceletStatusManual traceletStatus = iota
	traceletStatusUnused
	traceletStatusCreated
	traceletStatusReady
	traceletStatusDeleted
)

func (s traceletStatus) String() string {
	switch s {
	case traceletStatusManual:
		return "manual"
	case traceletStatusUnused:
		return "unused"
	case traceletStatusCreated:
		return "created"
	case traceletStatusReady:
		return "ready"
	case traceletStatusDeleted:
		return "deleted"
	default:
		return "unknown"
	}
}

type Tracelet struct {
	tailCallProg *bpflib.Module
	pm           *bpflib.PerfMap
	queueMap     *bpflib.Map
	cgroupPath   string
	cgroupId     uint64
	eventChan    chan []byte
	lostChan     chan uint64
	description  string
	eventBuffer  []Event
	utsns        uint32
	pid          uint64
	comm         string

	containerID  string
	uid          string
	namespace    string
	podname      string
	containeridx int

	status traceletStatus
}

type StraceBack struct {
	mainProg              *bpflib.Module
	cgroupMap             *bpflib.Map
	tailCallEnter         *bpflib.Map
	tailCallExit          *bpflib.Map
	syscallsDef           *bpflib.Map
	newContainerEventsMap *bpflib.PerfMap

	tracelets []*Tracelet

	eventChan chan []byte
	lostChan  chan uint64
	stopChan  chan struct{}

	podInformerChan chan podinformer.ContainerInfo
	podInformer     *podinformer.PodInformer

	procInformerChan chan procinformer.ProcInfo
	procInformer     *procinformer.ProcInformer
}

func NewTracer(withPodDiscovery bool, withProcInformer bool) (*StraceBack, error) {
	sb := &StraceBack{}

	obj := "straceback-main-bpf.o"
	if withPodDiscovery {
		obj = "straceback-guess-bpf.o"
	}

	buf, err := Asset(obj)
	if err != nil {
		return nil, fmt.Errorf("couldn't find asset: %s", err)
	}
	reader := bytes.NewReader(buf)

	sb.mainProg = bpflib.NewModuleFromReader(reader)
	if sb.mainProg == nil {
		return nil, fmt.Errorf("BPF not supported")
	}
	sb.mainProg = sb.mainProg

	sectionParams := make(map[string]bpflib.SectionParams)
	sectionParams["maps/container_events"] = bpflib.SectionParams{
		PerfRingBufferPageCount: 1,
	}
	err = sb.mainProg.Load(sectionParams)
	if err != nil {
		return nil, err
	}
	sb.cgroupMap = sb.mainProg.Map("cgroup_map")
	sb.tailCallEnter = sb.mainProg.Map("tail_call_enter")
	sb.tailCallExit = sb.mainProg.Map("tail_call_exit")
	sb.syscallsDef = sb.mainProg.Map("syscalls")

	for i, _ := range syscallNames {
		var nr uint64 = uint64(i)
		var def [6]uint64 = syscallGetDef(i)
		if err := sb.mainProg.UpdateElement(sb.syscallsDef, unsafe.Pointer(&nr), unsafe.Pointer(&def[0]), 0); err != nil {
			return nil, fmt.Errorf("error updating syscall def map: %v", err)
		}
	}

	err = sb.mainProg.EnableTracepoint("tracepoint/raw_syscalls/sys_enter")
	if err != nil {
		return nil, err
	}
	err = sb.mainProg.EnableTracepoint("tracepoint/raw_syscalls/sys_exit")
	if err != nil {
		return nil, err
	}

	sb.stopChan = make(chan struct{})
	sb.tracelets = make([]*Tracelet, C.MaxTracedPrograms)

	sb.podInformerChan = make(chan podinformer.ContainerInfo)
	sb.procInformerChan = make(chan procinformer.ProcInfo)

	if withPodDiscovery {
		// start pod informer
		sb.podInformer, _ = podinformer.NewPodInformer(sb.podInformerChan)

		// init tracelet pool
		for i := 0; i < int(C.MaxPooledPrograms); i++ {
			sb.tracelets[i], err = getDummyTracelet(sb.mainProg, sb.tailCallEnter, sb.tailCallExit, uint32(i))
			if err != nil {
				return nil, err
			}
		}

		// init queue map
		queueAvailProgs := sb.mainProg.Map("queue_avail_progs")
		var zero uint64 = 0
		var queue C.struct_queue_avail_progs_t = C.struct_queue_avail_progs_t{}
		for i := 0; i < int(C.MaxPooledPrograms); i++ {
			queue.indexes[i] = C.uint(i)
		}
		if err := sb.mainProg.UpdateElement(queueAvailProgs, unsafe.Pointer(&zero), unsafe.Pointer(&queue), 0); err != nil {
			return nil, fmt.Errorf("error updating queue of BPF programs: %v", err)
		}

		// init container_events
		sb.eventChan = make(chan []byte)
		sb.lostChan = make(chan uint64)

		sb.newContainerEventsMap, err = bpflib.InitPerfMap(sb.mainProg, "container_events", sb.eventChan, sb.lostChan)
		if err != nil {
			return nil, fmt.Errorf("error initializing perf map: %v", err)
		}

		sb.newContainerEventsMap.PollStart()

		// kprobe on free_uts_ns
		err = sb.mainProg.EnableKprobe("kprobe/free_uts_ns", 8)
		if err != nil {
			return nil, err
		}

		// guess
		err = guess(sb.mainProg)
		if err != nil {
			return nil, err
		}
	}

	if withProcInformer {
		sb.procInformer, _ = procinformer.NewProcInformer(sb.procInformerChan)
	}

	go sb.updater()

	return sb, nil
}

func (sb *StraceBack) updater() (out string) {
	ticker := time.NewTicker(1000 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-sb.stopChan:
			// On stop, stopChan will be closed but the other channels will
			// also be closed shortly after. The select{} has no priorities,
			// therefore, the "ok" value must be checked below.
			return

		case info, ok := <-sb.podInformerChan:
			if !ok {
				return // see explanation above
			}
			for i := 0; i < int(C.MaxPooledPrograms); i++ {
				if sb.tracelets[i].containerID != info.ContainerID {
					continue
				}
				sb.tracelets[i].uid = info.UID
				sb.tracelets[i].namespace = info.Namespace
				sb.tracelets[i].podname = info.Podname
				sb.tracelets[i].containeridx = info.Idx

				if sb.tracelets[i].status != traceletStatusCreated {
					continue
				}

				utsnsMap := sb.mainProg.Map("utsns_map")
				cStatus := C.struct_container_status_t{
					idx:    C.uint(i),
					status: C.ContainerStatusReady,
				}
				utsns := uint32(sb.tracelets[i].utsns)
				if err := sb.mainProg.UpdateElement(utsnsMap, unsafe.Pointer(&utsns), unsafe.Pointer(&cStatus), 0); err != nil {
					fmt.Printf("error updating utsns map: %v", err)
					return
				}
				sb.tracelets[i].status = traceletStatusReady
			}

		case <-ticker.C:
			if sb.podInformer != nil {
				for i := 0; i < int(C.MaxPooledPrograms); i++ {
					if sb.tracelets[i].containerID == "" {
						continue
					}
					var info *podinformer.ContainerInfo
					var err error
					if info, err = sb.podInformer.GetPodFromContainerID(sb.tracelets[i].containerID); err != nil {
						continue
					}

					sb.tracelets[i].uid = info.UID
					sb.tracelets[i].namespace = info.Namespace
					sb.tracelets[i].podname = info.Podname
					sb.tracelets[i].containeridx = info.Idx

					if sb.tracelets[i].status != traceletStatusCreated {
						continue
					}

					utsnsMap := sb.mainProg.Map("utsns_map")
					cStatus := C.struct_container_status_t{
						idx:    C.uint(i),
						status: C.ContainerStatusReady,
					}
					cUtsns := uint32(sb.tracelets[i].utsns)
					if err := sb.mainProg.UpdateElement(utsnsMap, unsafe.Pointer(&cUtsns), unsafe.Pointer(&cStatus), 0); err != nil {
						fmt.Printf("error updating utsns map: %v", err)
						return
					}
					sb.tracelets[i].status = traceletStatusReady
				}
			}

		case info, ok := <-sb.procInformerChan:
			if !ok {
				return // see explanation above
			}
			for i := 0; i < int(C.MaxPooledPrograms); i++ {
				if sb.tracelets[i].status != traceletStatusCreated {
					continue
				}
				if sb.tracelets[i].utsns != info.Utsns {
					continue
				}

				// if procInformer signals that it didn't find
				// this utsns in procfs or it is not a
				// Kubernetes pod
				if info.ContainerID == "" {
					// TODO: remove prog from the BPF map
					sb.CloseProg(uint32(i))
					continue
				}

				sb.tracelets[i].containerID = info.ContainerID

				if info, err := sb.podInformer.GetPodFromContainerID(sb.tracelets[i].containerID); err == nil {
					sb.tracelets[i].uid = info.UID
					sb.tracelets[i].namespace = info.Namespace
					sb.tracelets[i].podname = info.Podname
					sb.tracelets[i].containeridx = info.Idx

					utsnsMap := sb.mainProg.Map("utsns_map")
					cStatus := C.struct_container_status_t{
						idx:    C.uint(i),
						status: C.ContainerStatusReady,
					}
					cUtsns := uint32(sb.tracelets[i].utsns)
					if err := sb.mainProg.UpdateElement(utsnsMap, unsafe.Pointer(&cUtsns), unsafe.Pointer(&cStatus), 0); err != nil {
						fmt.Printf("error updating utsns map: %v", err)
						return
					}
					sb.tracelets[i].status = traceletStatusReady
				}
			}

		case data, ok := <-sb.eventChan:
			if !ok {
				return // see explanation above
			}
			eventC := (*C.struct_container_event_t)(unsafe.Pointer(&(data)[0]))

			containerID := C.GoString(&eventC.param[0])
			containerID = filepath.Base(containerID)
			containerID = strings.TrimSuffix(containerID, ".scope")
			if len(containerID) >= 64 {
				containerID = "docker://" + containerID[len(containerID)-64:]
			} else {
				containerID = ""
			}

			fmt.Printf("New container event: type %d: utsns %v assigned to slot %d (%q, pid: %v, tid: %v)\n",
				eventC.typ, eventC.utsns, eventC.idx, C.GoString(&eventC.comm[0]),
				eventC.pid>>32, eventC.pid&0xFFFFFFFF)
			fmt.Printf("    %s\n", containerID)

			if eventC.idx < C.uint(C.MaxPooledPrograms) {
				sb.tracelets[eventC.idx].utsns = uint32(eventC.utsns)
				sb.tracelets[eventC.idx].comm = C.GoString(&eventC.comm[0])

				if sb.podInformer != nil {
					if eventC.typ == C.ContainerEventTypeCreate {
						sb.tracelets[eventC.idx].pid = uint64(eventC.pid)
						sb.tracelets[eventC.idx].status = traceletStatusCreated
						if sb.procInformer != nil && !strings.HasPrefix(sb.tracelets[eventC.idx].comm, "runc") {
							sb.procInformer.LookupContainerID(sb.tracelets[eventC.idx].utsns)
						}
					} else if eventC.typ == C.ContainerEventTypeUpdate && containerID != "" {
						sb.tracelets[eventC.idx].containerID = containerID
						sb.tracelets[eventC.idx].status = traceletStatusReady
					} else if eventC.typ == C.ContainerEventTypeDelete {
						sb.tracelets[eventC.idx].status = traceletStatusDeleted
					}
				}
			}

		case lost, ok := <-sb.lostChan:
			if !ok {
				return // see explanation above
			}
			fmt.Printf("Lost data in the newContainerEventsMap: %v\n", lost)
		}
	}
}

func (sb *StraceBack) List() (out string) {
	for i := 0; i < int(C.MaxTracedPrograms); i++ {
		if sb.tracelets[i] == nil {
			continue
		}
		if sb.podInformer != nil {
			out += fmt.Sprintf("[%s] ", sb.tracelets[i].status)
			if sb.tracelets[i].containerID == "" {
				out += fmt.Sprintf("%d: trace not assigned to any container (%q, pid %d)\n",
					i, sb.tracelets[i].comm, sb.tracelets[i].pid>>32)
				continue
			}

			info, err := sb.podInformer.GetPodFromContainerID(sb.tracelets[i].containerID)
			if err == nil {
				out += fmt.Sprintf("%d: %s/%s #%d\n", i, info.Namespace, info.Podname, info.Idx)
			} else if sb.tracelets[i].podname != "" {
				out += fmt.Sprintf("%d: %s/%s #%d (deleted)\n",
					i,
					sb.tracelets[i].namespace,
					sb.tracelets[i].podname,
					sb.tracelets[i].containeridx)
			} else {
				out += fmt.Sprintf("%d: error: %s\n", i, err)
			}
		} else {
			out += fmt.Sprintf("%d: [%s] %s\n", i, sb.tracelets[i].description, sb.tracelets[i].cgroupPath)
		}
	}
	return
}

func getDummyTracelet(mainProg *bpflib.Module, tailCallEnter *bpflib.Map, tailCallExit *bpflib.Map, idx uint32) (*Tracelet, error) {
	tracelet := Tracelet{
		eventChan: make(chan []byte),
		lostChan:  make(chan uint64),
		status:    traceletStatusUnused,
	}

	buf, err := Asset("straceback-tailcall-bpf.o")
	if err != nil {
		return nil, fmt.Errorf("couldn't find asset: %s", err)
	}
	reader := bytes.NewReader(buf)

	m := bpflib.NewModuleFromReader(reader)
	if m == nil {
		return nil, fmt.Errorf("BPF not supported")
	}
	tracelet.tailCallProg = m

	sectionParams := make(map[string]bpflib.SectionParams)
	sectionParams["maps/events"] = bpflib.SectionParams{
		PerfRingBufferPageCount:    64,
		PerfRingBufferBackward:     true,
		PerfRingBufferOverwritable: true,
	}
	err = m.Load(sectionParams)
	if err != nil {
		return nil, err
	}
	pm, err := bpflib.InitPerfMap(m, "events", tracelet.eventChan, tracelet.lostChan)
	if err != nil {
		return nil, fmt.Errorf("error initializing perf map: %v", err)
	}
	pm.SetTimestampFunc(eventTimestamp)

	tracelet.pm = pm

	var fdEnter int = -1
	var fdExit int = -1
	for tp := range m.IterTracepointProgram() {
		if tp.Name == "tracepoint/raw_syscalls/sys_enter" {
			fdEnter = tp.Fd()
		}
		if tp.Name == "tracepoint/raw_syscalls/sys_exit" {
			fdExit = tp.Fd()
		}
	}
	if fdExit == -1 || fdExit == -1 {
		return nil, fmt.Errorf("couldn't find tracepoint fd")
	}
	if err := mainProg.UpdateElement(tailCallEnter, unsafe.Pointer(&idx), unsafe.Pointer(&fdEnter), 0); err != nil {
		return nil, fmt.Errorf("error updating tail call enter map: %v", err)
	}
	if err := mainProg.UpdateElement(tailCallExit, unsafe.Pointer(&idx), unsafe.Pointer(&fdExit), 0); err != nil {
		return nil, fmt.Errorf("error updating tail call exit map: %v", err)
	}

	return &tracelet, nil
}

func (sb *StraceBack) AddProg(cgroupPath string, description string) (uint32, error) {
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

	tracelet := Tracelet{
		description: description,
		cgroupPath:  cgroupPath,
		cgroupId:    cgroupId,
		eventChan:   make(chan []byte),
		lostChan:    make(chan uint64),
		status:      traceletStatusManual,
	}

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
	sectionParams["maps/events"] = bpflib.SectionParams{
		PerfRingBufferPageCount:    64,
		PerfRingBufferBackward:     true,
		PerfRingBufferOverwritable: true,
	}
	err = m.Load(sectionParams)
	if err != nil {
		return 0, err
	}
	tracelet.queueMap = m.Map("queue")
	pm, err := bpflib.InitPerfMap(m, "events", tracelet.eventChan, tracelet.lostChan)
	if err != nil {
		return 0, fmt.Errorf("error initializing perf map: %v", err)
	}
	pm.SetTimestampFunc(eventTimestamp)

	tracelet.pm = pm
	sb.tracelets[idx] = &tracelet

	var fdEnter int = -1
	var fdExit int = -1
	for tp := range m.IterTracepointProgram() {
		if tp.Name == "tracepoint/raw_syscalls/sys_enter" {
			fdEnter = tp.Fd()
		}
		if tp.Name == "tracepoint/raw_syscalls/sys_exit" {
			fdExit = tp.Fd()
		}
	}
	if fdExit == -1 || fdExit == -1 {
		return 0, fmt.Errorf("couldn't find tracepoint fd")
	}
	if err := sb.mainProg.UpdateElement(sb.cgroupMap, unsafe.Pointer(&cgroupId), unsafe.Pointer(&idx), 0); err != nil {
		return 0, fmt.Errorf("error updating tail call map: %v", err)
	}
	if err := sb.mainProg.UpdateElement(sb.tailCallEnter, unsafe.Pointer(&idx), unsafe.Pointer(&fdEnter), 0); err != nil {
		return 0, fmt.Errorf("error updating tail call enter map: %v", err)
	}
	if err := sb.mainProg.UpdateElement(sb.tailCallExit, unsafe.Pointer(&idx), unsafe.Pointer(&fdExit), 0); err != nil {
		return 0, fmt.Errorf("error updating tail call exit map: %v", err)
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

func (sb *StraceBack) DumpProgByName(name string) (out string, err error) {
	for i := 0; i < int(C.MaxTracedPrograms); i++ {
		if sb.tracelets[i] != nil && sb.tracelets[i].description == name {
			return sb.DumpProg(uint32(i))
		}
	}
	return "", fmt.Errorf("prog with name %q not found", name)
}

func (sb *StraceBack) DumpProgByCgroup(cgroupPath string) (out string, err error) {
	for i := 0; i < int(C.MaxTracedPrograms); i++ {
		if sb.tracelets[i] != nil && sb.tracelets[i].cgroupPath == cgroupPath {
			return sb.DumpProg(uint32(i))
		}
	}
	return "", fmt.Errorf("prog with cgroup %q not found", cgroupPath)
}

func (sb *StraceBack) DumpProg(id uint32) (out string, err error) {
	if id >= uint32(C.MaxTracedPrograms) || sb.tracelets[id] == nil {
		return "", fmt.Errorf("invalid index")
	}

	arr := sb.tracelets[id].pm.SwapAndDumpBackward()
	sb.tracelets[id].eventBuffer = append(sb.tracelets[id].eventBuffer, eventsToGo(arr)...)
	if len(sb.tracelets[id].eventBuffer) > maxEvents {
		sb.tracelets[id].eventBuffer = sb.tracelets[id].eventBuffer[len(sb.tracelets[id].eventBuffer)-maxEvents:]
	}
	out = eventsToString(sb.tracelets[id].eventBuffer)
	return
}

func (sb *StraceBack) DumpAll() (out string, err error) {
	for i := 0; i < int(C.MaxTracedPrograms); i++ {
		if sb.tracelets[i] == nil {
			continue
		}
		if sb.tracelets[i].utsns == 0 {
			continue
		}
		fmt.Printf("Program %q: utsns=%v\n", sb.tracelets[i].comm, sb.tracelets[i].utsns)
		out2, err2 := sb.DumpProg(uint32(i))
		if err2 != nil {
			fmt.Printf("%v\n", err)
			return
		}
		fmt.Printf("%s", out2)
	}
	return
}

func (sb *StraceBack) DumpPod(namespace, podname string, containerIndex int) (out string, err error) {
	if sb.podInformer == nil {
		return "", fmt.Errorf("no pod informer")
	}

	containerID, err2 := sb.podInformer.GetContainerIDFromPod(namespace, podname, containerIndex)
	if err2 != nil {
		return "", err2
	}

	for i := 0; i < int(C.MaxTracedPrograms); i++ {
		if sb.tracelets[i] == nil {
			continue
		}
		if sb.tracelets[i].containerID == containerID {
			out, err = sb.DumpProg(uint32(i))
			return
		}
	}
	return "", fmt.Errorf("cannot find trace #%d for pod %s/%s", containerIndex, namespace, podname)
}

func (sb *StraceBack) CloseProg(id uint32) (err error) {
	sb.tracelets[id].tailCallProg.Close()
	sb.tracelets[id] = nil
	return
}

func (sb *StraceBack) CloseProgByName(name string) (err error) {
	for i := 0; i < int(C.MaxTracedPrograms); i++ {
		if sb.tracelets[i] != nil && sb.tracelets[i].description == name {
			sb.tracelets[i].tailCallProg.Close()
			sb.tracelets[i] = nil
		}
	}
	return
}

func (sb *StraceBack) Stop() {
	close(sb.stopChan)
	sb.newContainerEventsMap.PollStop()
	for i, _ := range sb.tracelets {
		if sb.tracelets[i] != nil {
			sb.tracelets[i].pm.PollStop()
		}
	}
	sb.mainProg.Close()
}
