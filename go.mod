module github.com/kinvolk/traceloop

go 1.12

require (
	github.com/iovisor/gobpf v0.0.0-20190329163444-e0d8d785d368
	github.com/sirupsen/logrus v1.6.0
	github.com/syndtr/gocapability v0.0.0-20180916011248-d98352740cb2
	golang.org/x/crypto v0.0.0-20220314234659-1baeb1ce4c0b // indirect
	golang.org/x/sys v0.1.0
	k8s.io/api v0.20.6
	k8s.io/apimachinery v0.20.6
	k8s.io/client-go v0.20.6
	k8s.io/klog v1.0.0
)

replace github.com/iovisor/gobpf => github.com/kinvolk/gobpf v0.0.0-20191127154002-f0f89e7c6fd1
