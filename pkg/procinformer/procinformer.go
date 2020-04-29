package procinformer

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/kinvolk/traceloop/pkg/podcgroup"
)

type ProcInfo struct {
	PodUID      string
	ContainerID string
	Utsns       uint32
}

type ProcInformer struct {
	// key:   Utsns
	lookups map[uint32]struct{}
	mutex   *sync.Mutex

	stopChan         chan struct{}
	procInformerChan chan ProcInfo
}

func NewProcInformer(procInformerChan chan ProcInfo) (*ProcInformer, error) {
	c := &ProcInformer{
		lookups: make(map[uint32]struct{}),
		mutex:   &sync.Mutex{},

		stopChan:         make(chan struct{}),
		procInformerChan: procInformerChan,
	}

	go func() {
		ticker := time.NewTicker(1000 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-c.stopChan:
				return
			case <-ticker.C:
				err := c.update()
				if err != nil {
					fmt.Printf("%s\n", err)
					return
				}
			}
		}
	}()

	return c, nil
}

func (p *ProcInformer) update() error {
	p.mutex.Lock()
	if len(p.lookups) == 0 {
		p.mutex.Unlock()
		return nil
	}
	lookups := p.lookups
	p.lookups = make(map[uint32]struct{})
	p.mutex.Unlock()

	procPath := "/proc"

	files, err := ioutil.ReadDir(procPath)
	if err != nil {
		return err
	}
	for _, fileInfo := range files {
		_, err := strconv.Atoi(fileInfo.Name())
		if err != nil {
			continue
		}

		var stat syscall.Stat_t
		if err := syscall.Stat(filepath.Join(procPath, fileInfo.Name(), "ns", "uts"), &stat); err != nil {
			// Process might have terminated
			continue
		}
		utsns := uint32(stat.Ino)

		// Defined in include/linux/proc_ns.h
		procUtsInitIno := uint32(0xEFFFFFFE)
		if utsns == procUtsInitIno {
			continue
		}

		if _, ok := lookups[utsns]; !ok {
			continue
		}

		cgroupProcFile := filepath.Join(procPath, fileInfo.Name(), "cgroup")
		podUid, containerID := podcgroup.ExtractIdFromCgroupProcFile(cgroupProcFile)
		if podUid == "" || containerID == "" {
			continue
		}

		fmt.Printf("found containerID %s for utsns %d\n", containerID, utsns)
		delete(lookups, utsns)
		p.procInformerChan <- ProcInfo{
			Utsns:       utsns,
			ContainerID: containerID,
			PodUID:      podUid,
		}
	}
	for utsns, _ := range lookups {
		p.procInformerChan <- ProcInfo{
			Utsns:       utsns,
			ContainerID: "",
			PodUID:      "",
		}
	}

	return nil
}

func (p *ProcInformer) LookupContainerID(utsns uint32) {
	fmt.Printf("lookup for utsns %d\n", utsns)
	p.mutex.Lock()
	p.lookups[utsns] = struct{}{}
	p.mutex.Unlock()
}
