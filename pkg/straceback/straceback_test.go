package straceback

import (
	"testing"
)

func TestExtractIdFromCgroupPath(t *testing.T) {
	type testCase struct {
		cgroupPath  string
		podUid      string
		containerID string
	}

	var tests []testCase = []testCase{
		testCase{
			"/sys/fs/cgroup/systemd/kubepods/besteffort/pod91a8fc3a-0ecf-48b4-81bf-78a7275d348c/f75aff467357c5d0ddd47cb7ad87ed38746e018992586ff66198a5c11218f634",
			"91a8fc3a-0ecf-48b4-81bf-78a7275d348c",
			"docker://f75aff467357c5d0ddd47cb7ad87ed38746e018992586ff66198a5c11218f634",
		},
		testCase{
			"/sys/fs/cgroup/systemd/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod5759a1ae_36ca_48a8_b20a_b0b5c8a90fb8.slice/docker-c8b38413c88eefe063b8cd3f01c16be5e3bda9693a19a68a88807baca9feb937.scope",
			"5759a1ae-36ca-48a8-b20a-b0b5c8a90fb8",
			"docker://c8b38413c88eefe063b8cd3f01c16be5e3bda9693a19a68a88807baca9feb937",
		},
	}

	for _, test := range tests {
		podUid, containerID := extractIdFromCgroupPath(test.cgroupPath)
		if podUid != test.podUid {
			t.Errorf("extractIdFromCgroupPath(%s)->podUid: got %s; want %s", test.cgroupPath, podUid, test.podUid)
		}
		if containerID != test.containerID {
			t.Errorf("extractIdFromCgroupPath(%s)->containerID: got %s; want %s", test.cgroupPath, containerID, test.containerID)
		}
	}
}
