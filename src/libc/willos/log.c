#include <willos/log.h>

#ifndef __is_libk
#include <fcntl.h>
#include <stdio.h>
#include <sys/syscall.h>

static int com1_fd = 0;

void willos_log_init()
{
  int fd = open("/dev/com1", O_WRONLY);

  if (fd < 3) {
    return;
  }

  // Write nothing to force-clear the serial transmit queue.
  write(fd, "", 1);

  com1_fd = fd;
}

void willos_log_deinit()
{
  if (com1_fd < 3) {
    return;
  }

  close(com1_fd);
}

void willos_log_putchar(char c, void* arg)
{
  (void)(*arg);

  if (com1_fd < 3) {
    return;
  }

  // Make sure we write a null-terminated string.
  write(com1_fd, (char[]){ c, '\0' }, 1);
}

#endif
