package podcgroup

import (
	"bufio"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	cgroupProcFileContentRegexp1 *regexp.Regexp
	cgroupProcFileContentRegexp2 *regexp.Regexp

	podIDRegexp, containerIDRegexp         *regexp.Regexp
	podIDMatchCount, containerIDMatchCount int
)

func init() {
	// idx 0 is whole match, idx 1 is the ID (potentially with underlines instead of dashes)
	podIDRegexp = regexp.MustCompile(`pod([a-f0-9]{8}[-_][a-f0-9]{4}[-_][a-f0-9]{4}[-_][a-f0-9]{4}[-_][a-f0-9]{12})`)
	podIDMatchCount = 2

	// the docker- or crio- prefix is optional,
	// idx 0 is whole match, idx 1 is the prefix without dash or empty if none, idx 2 is the ID
	containerIDRegexp = regexp.MustCompile(`(?:([a-z]*)-)?([0-9a-f]{64})`)
	containerIDMatchCount = 3

	// Examples:
	// 1:name=systemd:/kubepods/burstable/pod533bebda-632d-4a45-9f32-237bcae5b1fc/f2c9e02d3140d5d72f23640b79596dcb043cc3ee818fb61507ff2dfb63dd0211
	// 1:name=systemd:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod1aecc643_23ea_11e9_beec_06c846f19394.slice/docker-da9977a4f9abe14ab2fa87d3780d92fd615b97cc3107fcd4a851f01857cb8ff8.scope
	// 1:name=systemd:/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod12345678_1234_1234_1234_123456789012.slice/crio-f75aff467357c5d0ddd47cb7ad87ed38746e018992586ff66198a5c11218f634.scope
	cgroupProcFileContentRegexp1 = regexp.MustCompile("\n1:name=systemd:.*/kubepods.*[/-]pod([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}).*/([0-9a-f]{64})")
	cgroupProcFileContentRegexp2 = regexp.MustCompile("\n1:name=systemd:.*/kubepods.*[/-]pod([a-f0-9]{8}_[a-f0-9]{4}_[a-f0-9]{4}_[a-f0-9]{4}_[a-f0-9]{12}).*/([a-z]*)-([0-9a-f]{64})")

}

// podContainerIDExtractor finds the pod uid and container id from a cgroup
// path.
func podContainerIDExtractor(cgroupPath string) (podUid, containerID string) {
	dir, containerIDSegment := filepath.Split(cgroupPath)
	podIDSegment := filepath.Base(dir)

	containerIDMatches := containerIDRegexp.FindStringSubmatch(containerIDSegment)
	if len(containerIDMatches) != containerIDMatchCount {
		return
	}

	podIDMatches := podIDRegexp.FindStringSubmatch(podIDSegment)
	if len(podIDMatches) != podIDMatchCount {
		return
	}

	containerRuntime := containerIDMatches[1]
	if containerRuntime == "" {
		containerRuntime = "docker"
	}
	if containerRuntime == "crio" {
		containerRuntime = "cri-o"
	}
	if containerRuntime != "docker" && containerRuntime != "cri-o" {
		return
	}

	podUid = podIDMatches[1]
	podUid = strings.Replace(podUid, "_", "-", -1)
	containerID = containerRuntime + "://" + containerIDMatches[2]

	return
}

// ExtractIDFromCgroupPath finds the pod uid and container id from a cgroup
// path.
//
// Examples of paths that can be parsed:
// /sys/fs/cgroup/systemd/kubepods/besteffort/pod91a8fc3a-0ecf-48b4-81bf-78a7275d348c/f75aff467357c5d0ddd47cb7ad87ed38746e018992586ff66198a5c11218f634
// /sys/fs/cgroup/systemd/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod5759a1ae_36ca_48a8_b20a_b0b5c8a90fb8.slice/docker-c8b38413c88eefe063b8cd3f01c16be5e3bda9693a19a68a88807baca9feb937.scope
// /sys/fs/cgroup/systemd/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod12345678_1234_1234_1234_123456789012.slice/crio-f75aff467357c5d0ddd47cb7ad87ed38746e018992586ff66198a5c11218f634.scope
func ExtractIDFromCgroupPath(cgroupPath string) (podUid, containerID string) {
	if !strings.HasPrefix(cgroupPath, "/sys/fs/cgroup/systemd/") {
		return
	}

	return podContainerIDExtractor(cgroupPath)
}

// ExtractIDFromCgroupProcFile finds the pod uid and container id from a cgroup
// proc file.
//
// Examples of paths that can be parsed: "/proc/42/cgroup".
func ExtractIDFromCgroupProcFile(cgroupProcFile string) (podUid, containerID string) {
	cgroupProcFileContent, err := ioutil.ReadFile(cgroupProcFile)
	if err != nil {
		// Process might have terminated
		return
	}
	return extractIDFromCgroupProcFileContent(string(cgroupProcFileContent))
}

func extractIDFromCgroupProcFileContent(cgroupProcFileContent string) (podUid, containerID string) {
	scanner := bufio.NewScanner(strings.NewReader(cgroupProcFileContent))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "1:name=systemd:") {
			continue
		}
		return podContainerIDExtractor(line)
	}
	return
}
