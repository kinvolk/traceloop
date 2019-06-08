module github.com/kinvolk/traceloop

go 1.12

require (
	github.com/iovisor/gobpf v0.0.0-20190329163444-e0d8d785d368
	github.com/mauriciovasquezbernal/gobpf v0.0.0-20190608151755-5f86437596b2 // indirect
)

replace github.com/iovisor/gobpf => github.com/mauriciovasquezbernal/gobpf v0.0.0-20190608151755-5f86437596b2
