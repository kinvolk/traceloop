package procinformer

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"syscall"
	"time"
)

type ProcInfo struct {
	ContainerID string
	Utsns       uint32
}

type ProcInformer struct {
	// key:   Utsns
	lookups map[uint32]struct{}
	mutex   *sync.Mutex

	stopChan         chan struct{}
	procInformerChan chan ProcInfo

	cgroupRegexp *regexp.Regexp
}

func NewProcInformer(procInformerChan chan ProcInfo) (*ProcInformer, error) {
	c := &ProcInformer{
		lookups: make(map[uint32]struct{}),
		mutex:   &sync.Mutex{},

		stopChan:         make(chan struct{}),
		procInformerChan: procInformerChan,
	}

	// Examples:
	// 1:name=systemd:/kubepods/burstable/pod533bebda-632d-4a45-9f32-237bcae5b1fc/f2c9e02d3140d5d72f23640b79596dcb043cc3ee818fb61507ff2dfb63dd0211
	// 1:name=systemd:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod1aecc643_23ea_11e9_beec_06c846f19394.slice/docker-da9977a4f9abe14ab2fa87d3780d92fd615b97cc3107fcd4a851f01857cb8ff8.scope
	c.cgroupRegexp, _ = regexp.Compile("\n1:name=systemd:.*/kubepods.*[/-]pod([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}).*/([0-9a-f]{64})")

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

		cgroupContent, err := ioutil.ReadFile(filepath.Join(procPath, fileInfo.Name(), "cgroup"))
		if err != nil {
			// Process might have terminated
			continue
		}

		matches := p.cgroupRegexp.FindStringSubmatch(string(cgroupContent))
		if len(matches) != 3 {
			continue
		}
		//podUid := matches[1]
		containerID := "docker://" + matches[2]
		//fmt.Printf("pid %d utsns %d pod %s containerID %s\n", pid, utsns, podUid, containerID)

		if _, ok := lookups[utsns]; !ok {
			continue
		}
		delete(lookups, utsns)

		fmt.Printf("found containerID %s for utsns %d\n", containerID, utsns)
		p.procInformerChan <- ProcInfo{
			Utsns:       utsns,
			ContainerID: containerID,
		}
	}
	for utsns, _ := range lookups {
		p.procInformerChan <- ProcInfo{
			Utsns:       utsns,
			ContainerID: "",
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
