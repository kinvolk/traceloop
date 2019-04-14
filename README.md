# straceback

Example:
```
sudo -E ./straceback serve
...
curl --unix-socket /run/straceback.socket 'http://localhost/add?cgrouppath=/sys/fs/cgroup/unified/test01/'
curl --unix-socket /run/straceback.socket 'http://localhost/dump?id=1'
```
