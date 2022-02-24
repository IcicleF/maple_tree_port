# maple_tree_port

This project is an attempt to port maple tree from Orace Linux UEK (5.17-rc4) to Linux kernel version 4.15.0.

## Usage

```bash
make
sudo insmod maple.ko
dmesg | grep maple
```

User-space code:

```cpp
static const int MAPLE_LOCK = 0, MAPLE_UNLOCK = 1;
int fd = open("/dev/maple_tree_dev", O_RDONLY);

unsigned long left = 0, right = 5;    // [0, 5)
int ret = ioctl(fd, MAPLE_LOCK, (right << 32) | left);    // compose the range into uint64_t
int ret = ioctl(fd, MAPLE_UNLOCK, left);                  // any integer within [0, 5)

close(fd);
```
