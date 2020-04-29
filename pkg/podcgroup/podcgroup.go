package podcgroup

import (
	"io/ioutil"
	"regexp"
	"strings"
)

// ExtractIdFromCgroupPath finds the pod uid and container id from a cgroup
// path.
//
// Examples of paths that can be parsed:
// /sys/fs/cgroup/systemd/kubepods/besteffort/pod91a8fc3a-0ecf-48b4-81bf-78a7275d348c/f75aff467357c5d0ddd47cb7ad87ed38746e018992586ff66198a5c11218f634
// /sys/fs/cgroup/systemd/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod5759a1ae_36ca_48a8_b20a_b0b5c8a90fb8.slice/docker-c8b38413c88eefe063b8cd3f01c16be5e3bda9693a19a68a88807baca9feb937.scope
// /sys/fs/cgroup/systemd/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod12345678_1234_1234_1234_123456789012.slice/crio-f75aff467357c5d0ddd47cb7ad87ed38746e018992586ff66198a5c11218f634.scope
func ExtractIdFromCgroupPath(cgroupPath string) (podUid, containerID string) {
	if cgroupPath == "" {
		return
	}

	pathRegexp1, _ := regexp.Compile("^/sys/fs/cgroup/systemd.*/kubepods.*[/-]pod([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}).*/([0-9a-f]{64})")
	pathRegexp2, _ := regexp.Compile("^/sys/fs/cgroup/systemd.*/kubepods.*[/-]pod([a-f0-9]{8}_[a-f0-9]{4}_[a-f0-9]{4}_[a-f0-9]{4}_[a-f0-9]{12}).*/([a-z]*)-([0-9a-f]{64}).scope")

	matches := pathRegexp1.FindStringSubmatch(cgroupPath)
	if len(matches) == 3 {
		podUid = matches[1]
		containerID = "docker://" + matches[2]
		return
	}

	matches = pathRegexp2.FindStringSubmatch(cgroupPath)
	if len(matches) == 4 {
		podUid = strings.Replace(matches[1], "_", "-", -1)
		engine := matches[2]
		if engine == "crio" {
			engine = "cri-o"
		}
		containerID = engine + "://" + matches[3]
		return
	}

	return
}

// ExtractIdFromCgroupPath finds the pod uid and container id from a cgroup
// proc file.
//
// Examples of paths that can be parsed: "/proc/42/cgroup".
func ExtractIdFromCgroupProcFile(cgroupProcFile string) (podUid, containerID string) {
	cgroupProcFileContent, err := ioutil.ReadFile(cgroupProcFile)
	if err != nil {
		// Process might have terminated
		return
	}
	return extractIdFromCgroupProcFileContent(string(cgroupProcFileContent))
}

func extractIdFromCgroupProcFileContent(cgroupProcFileContent string) (podUid, containerID string) {
	// Examples:
	// 1:name=systemd:/kubepods/burstable/pod533bebda-632d-4a45-9f32-237bcae5b1fc/f2c9e02d3140d5d72f23640b79596dcb043cc3ee818fb61507ff2dfb63dd0211
	// 1:name=systemd:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod1aecc643_23ea_11e9_beec_06c846f19394.slice/docker-da9977a4f9abe14ab2fa87d3780d92fd615b97cc3107fcd4a851f01857cb8ff8.scope
	// 1:name=systemd:/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod12345678_1234_1234_1234_123456789012.slice/crio-f75aff467357c5d0ddd47cb7ad87ed38746e018992586ff66198a5c11218f634.scope
	cgroupRegexp1, _ := regexp.Compile("\n1:name=systemd:.*/kubepods.*[/-]pod([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}).*/([0-9a-f]{64})")
	cgroupRegexp2, _ := regexp.Compile("\n1:name=systemd:.*/kubepods.*[/-]pod([a-f0-9]{8}_[a-f0-9]{4}_[a-f0-9]{4}_[a-f0-9]{4}_[a-f0-9]{12}).*/([a-z]*)-([0-9a-f]{64})")

	matches := cgroupRegexp1.FindStringSubmatch(string(cgroupProcFileContent))
	if len(matches) == 3 {
		podUid = strings.Replace(matches[1], "_", "-", -1)
		containerID = "docker://" + matches[2]
		return
	}

	matches = cgroupRegexp2.FindStringSubmatch(string(cgroupProcFileContent))
	if len(matches) == 4 {
		podUid = strings.Replace(matches[1], "_", "-", -1)
		engine := matches[2]
		if engine == "crio" {
			engine = "cri-o"
		}
		containerID = engine + "://" + matches[3]
		return
	}
	return
}
