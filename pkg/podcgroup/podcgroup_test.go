package podcgroup

import (
	"testing"
)

func TestExtractIDFromCgroupPath(t *testing.T) {
	type testCase struct {
		cgroupPath  string
		podUID      string
		containerID string
	}

	var tests []testCase = []testCase{
		// kubelet with --cgroup-driver=cgroupfs and docker
		{
			"/sys/fs/cgroup/systemd/kubepods/besteffort/pod91a8fc3a-0ecf-48b4-81bf-78a7275d348c/f75aff467357c5d0ddd47cb7ad87ed38746e018992586ff66198a5c11218f634",
			"91a8fc3a-0ecf-48b4-81bf-78a7275d348c",
			"docker://f75aff467357c5d0ddd47cb7ad87ed38746e018992586ff66198a5c11218f634",
		},
		// kubelet with --cgroup-driver=systemd and docker
		{
			"/sys/fs/cgroup/systemd/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod5759a1ae_36ca_48a8_b20a_b0b5c8a90fb8.slice/docker-c8b38413c88eefe063b8cd3f01c16be5e3bda9693a19a68a88807baca9feb937.scope",
			"5759a1ae-36ca-48a8-b20a-b0b5c8a90fb8",
			"docker://c8b38413c88eefe063b8cd3f01c16be5e3bda9693a19a68a88807baca9feb937",
		},
		// kubelet with --cgroup-driver=systemd and --cgroup-root=/container.slice and docker
		{
			"/sys/fs/cgroup/systemd/container.slice/container-kubepods.slice/container-kubepods-besteffort.slice/container-kubepods-besteffort-pod5759a1ae_36ca_48a8_b20a_b0b5c8a90fb8.slice/docker-c8b38413c88eefe063b8cd3f01c16be5e3bda9693a19a68a88807baca9feb937.scope",
			"5759a1ae-36ca-48a8-b20a-b0b5c8a90fb8",
			"docker://c8b38413c88eefe063b8cd3f01c16be5e3bda9693a19a68a88807baca9feb937",
		},
		// kubelet with --cgroup-driver=systemd and cri-o
		{
			"/sys/fs/cgroup/systemd/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod12345678_1234_1234_1234_123456789012.slice/crio-f75aff467357c5d0ddd47cb7ad87ed38746e018992586ff66198a5c11218f634.scope",
			"12345678-1234-1234-1234-123456789012",
			"cri-o://f75aff467357c5d0ddd47cb7ad87ed38746e018992586ff66198a5c11218f634",
		},
		// kubelet with --cgroup-driver=systemd and --cgroup-root=/container.slice and cri-o
		{
			"/sys/fs/cgroup/systemd/container.slice/container-kubepods.slice/container-kubepods-burstable.slice/container-kubepods-burstable-pod12345678_1234_1234_1234_123456789012.slice/crio-f75aff467357c5d0ddd47cb7ad87ed38746e018992586ff66198a5c11218f634.scope",
			"12345678-1234-1234-1234-123456789012",
			"cri-o://f75aff467357c5d0ddd47cb7ad87ed38746e018992586ff66198a5c11218f634",
		},
	}

	for _, test := range tests {
		podUID, containerID := ExtractIDFromCgroupPath(test.cgroupPath)
		if podUID != test.podUID {
			t.Errorf("ExtractIDFromCgroupPath(%s)->podUID: got %s; want %s",
				test.cgroupPath, podUID, test.podUID)
		}
		if containerID != test.containerID {
			t.Errorf("ExtractIDFromCgroupPath(%s)->containerID: got %s; want %s",
				test.cgroupPath, containerID, test.containerID)
		}
	}
}

func TestExtractIDFromCgroupProcFileContent(t *testing.T) {
	type testCase struct {
		cgroupProcFileContent string
		podUID                string
		containerID           string
	}

	var tests []testCase = []testCase{
		// kubelet with --cgroup-driver=cgroupfs and docker
		{
			"\n1:name=systemd:/kubepods/burstable/pod533bebda-632d-4a45-9f32-237bcae5b1fc/f2c9e02d3140d5d72f23640b79596dcb043cc3ee818fb61507ff2dfb63dd0211",
			"533bebda-632d-4a45-9f32-237bcae5b1fc",
			"docker://f2c9e02d3140d5d72f23640b79596dcb043cc3ee818fb61507ff2dfb63dd0211",
		},
		// kubelet with --cgroup-driver=systemd and docker
		{
			"\n1:name=systemd:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod1aecc643_23ea_11e9_beec_06c846f19394.slice/docker-da9977a4f9abe14ab2fa87d3780d92fd615b97cc3107fcd4a851f01857cb8ff8.scope",
			"1aecc643-23ea-11e9-beec-06c846f19394",
			"docker://da9977a4f9abe14ab2fa87d3780d92fd615b97cc3107fcd4a851f01857cb8ff8",
		},
		// kubelet with --cgroup-driver=systemd and --cgroup-root=/container.slice and docker
		{
			"\n1:name=systemd:/container.slice/container-kubepods.slice/container-kubepods-besteffort.slice/container-kubepods-besteffort-pod1aecc643_23ea_11e9_beec_06c846f19394.slice/docker-da9977a4f9abe14ab2fa87d3780d92fd615b97cc3107fcd4a851f01857cb8ff8.scope",
			"1aecc643-23ea-11e9-beec-06c846f19394",
			"docker://da9977a4f9abe14ab2fa87d3780d92fd615b97cc3107fcd4a851f01857cb8ff8",
		},
		// kubelet with --cgroup-driver=systemd and cri-o
		{
			"\n1:name=systemd:/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod12345678_1234_1234_1234_123456789012.slice/crio-f75aff467357c5d0ddd47cb7ad87ed38746e018992586ff66198a5c11218f634.scope",
			"12345678-1234-1234-1234-123456789012",
			"cri-o://f75aff467357c5d0ddd47cb7ad87ed38746e018992586ff66198a5c11218f634",
		},
		// don't catch cri-o connmon scopes
		{
			"\n1:name=systemd:/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod11111111_1111_1111_1111_111111111111.slice/crio-conmon-1111111111111111111111111111111111111111111111111111111111111111.scope",
			"",
			"",
		},
	}

	for _, test := range tests {
		podUID, containerID := extractIDFromCgroupProcFileContent(test.cgroupProcFileContent)
		if podUID != test.podUID {
			t.Errorf("extractIDFromCgroupProcFileContent(%s)->podUID: got %s; want %s",
				test.cgroupProcFileContent, podUID, test.podUID)
		}
		if containerID != test.containerID {
			t.Errorf("extractIDFromCgroupProcFileContent(%s)->containerID: got %s; want %s",
				test.cgroupProcFileContent, containerID, test.containerID)
		}
	}

}
