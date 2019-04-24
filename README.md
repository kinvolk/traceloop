# straceback

## On the command line

```
sudo -E ./straceback /sys/fs/cgroup/unified/system.slice/sshd.service
```

## With Docker

```
docker run --rm -v /sys/kernel/debug:/sys/kernel/debug -v /sys/fs/cgroup:/sys/fs/cgroup -v /sys/fs/bpf:/sys/fs/bpf -v /run:/run --privileged kinvolk/straceback
```

## With HTTP interface

```
sudo -E ./straceback serve
...

$sudo curl --unix-socket /run/straceback.socket 'http://localhost/add?name=sshd&cgrouppath=/sys/fs/cgroup/unified/system.slice/sshd.service'
added as id 0
$ sudo curl --unix-socket /run/straceback.socket 'http://localhost/list'
0: [sshd] /sys/fs/cgroup/unified/system.slice/sshd.service
$ sudo curl --unix-socket /run/straceback.socket 'http://localhost/dump-by-cgroup?cgroup=/sys/fs/cgroup/unified/system.slice/sshd.service'
...

```

## Example of logs

```
728974746616427 cpu#3 pid 17976 [sshd] close(fd)
728974746623494 cpu#3 pid 17976 [sshd] openat(dfd, filename, flags, mode)
728974746627090 cpu#3 pid 17976 [sshd] read(fd, buf, count)
728974746629674 cpu#3 pid 17976 [sshd] fstat()
728974746632360 cpu#3 pid 17976 [sshd] mmap(addr, len, prot, flags, fd, off)
```
