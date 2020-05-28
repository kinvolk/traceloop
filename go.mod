module github.com/kinvolk/traceloop

go 1.12

require (
	github.com/gophercloud/gophercloud v0.4.0 // indirect
	github.com/iovisor/gobpf v0.0.0-20190329163444-e0d8d785d368
	github.com/sirupsen/logrus v1.6.0
	github.com/syndtr/gocapability v0.0.0-20180916011248-d98352740cb2
	golang.org/x/crypto v0.0.0-20191002192127-34f69633bfdc // indirect
	golang.org/x/time v0.0.0-20190921001708-c4c64cad1fd0 // indirect
	k8s.io/api v0.17.4
	k8s.io/apimachinery v0.17.4
	k8s.io/client-go v12.0.0+incompatible
	k8s.io/klog v1.0.0
	k8s.io/utils v0.0.0-20190923111123-69764acb6e8e // indirect
)

replace github.com/iovisor/gobpf => github.com/kinvolk/gobpf v0.0.0-20191127154002-f0f89e7c6fd1
