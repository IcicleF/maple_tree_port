#include <cstdlib>
#include <cstdio>
#include <cassert>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

inline unsigned long compose(unsigned left, unsigned right)
{
    return ((unsigned long)right << 32) | left;
}

static const int MAPLE_LOCK = 0, MAPLE_UNLOCK = 1;

int main()
{
    int fd = open("/dev/maple_tree_dev", O_RDONLY);
    int ret;

    ret = ioctl(fd, MAPLE_LOCK, compose(0, 6)); printf("%d\n", ret);
    ret = ioctl(fd, MAPLE_LOCK, compose(5, 10)); printf("%d\n", ret);
    ret = ioctl(fd, MAPLE_LOCK, compose(6, 10)); printf("%d\n", ret);
    ret = ioctl(fd, MAPLE_UNLOCK, 0); printf("%d\n", ret);
    ret = ioctl(fd, MAPLE_UNLOCK, 6); printf("%d\n", ret);
    ret = ioctl(fd, MAPLE_LOCK, compose(5, 10)); printf("%d\n", ret);

    close(fd);
    return 0;
}