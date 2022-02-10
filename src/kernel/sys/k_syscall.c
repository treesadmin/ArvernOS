#include <sys/k_syscall.h>

#include <arch/sys.h>
#include <arvern/utils.h>
#include <osinfo.h>
#include <proc/descriptor.h>
#include <stdlib.h>
#include <string.h>
#include <sys/logging.h>
#include <sys/syscall.h>
#include <time/timer.h>

#define TIOCGWINSZ 0x5413
#define SET_FSBASE 0x1002
#define PAGE_SIZE  4096
#define HEAP_PAGES 20

struct iovec
{
  uintptr_t base;
  ssize_t len;
} __attribute__((packed));

struct utsname
{
  char sysname[65];
  char nodename[65];
  char release[65];
  char version[65];
  char machine[65];
};

static struct utsname uname = { .sysname = KERNEL_NAME,
                                .nodename = "",
                                .release = KERNEL_VERSION,
                                .version = KERNEL_GIT_HASH,
                                .machine = KERNEL_TARGET };

struct pollfd
{
  int fd;
  short events;
  short revents;
};

typedef unsigned int nfds_t;

int k_return_zero();
int k_writev(int fd, struct iovec* iov, int iovcnt);
int k_ioctl(int fd, int request, void* ptr);
void* k_mmap(void* addr,
             size_t length,
             int prot,
             int flags,
             int fd,
             off_t offset);
char* k_getcwd(char* buf, size_t size);
int k_uname(struct utsname* buf);
int k_dup2(int oldfd, int newfd);
int k_connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen);
int k_getsockname(int sockfd,
                  struct sockaddr* restrict addr,
                  socklen_t* restrict addrlen);
int k_poll(struct pollfd* fds, nfds_t nfds, int timeout);

typedef void (*syscall_ptr_t)(void);

syscall_ptr_t syscall_handlers[350] = {
  [0 ... 349] = (syscall_ptr_t)k_not_implemented,
};

static const char* syscall_names[350] = {
  [0 ... 349] = "(unknown)",
};

int k_poll(struct pollfd* fds, nfds_t nfds, int timeout)
{
  UNUSED(*fds);
  UNUSED(nfds);
  MAYBE_UNUSED(timeout);

  SYS_DEBUG("timeout=%d", timeout);

  uint64_t now = timer_uptime_microseconds();

  while (timer_uptime_microseconds() < (now + 1000)) {
    ;
  }

  return 0;
}

int k_getsockname(int sockfd, struct sockaddr* addr, socklen_t* addrlen)
{
  descriptor_t* desc = get_descriptor(sockfd);

  memcpy(addr, &desc->addr, desc->addr_len);
  *addrlen = desc->addr_len;

  return 0;
}

int k_connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen)
{
  descriptor_t* desc = get_descriptor(sockfd);

  memcpy(&desc->addr, addr, addrlen);
  desc->addr_len = addrlen;

  return 0;
}

int k_dup2(int oldfd, int newfd)
{
  SYS_DEBUG("oldfd=%d newfd=%d", oldfd, newfd);

  duplicate_descriptor(oldfd, newfd);

  return newfd;
}

int k_uname(struct utsname* buf)
{
  memcpy(buf, &uname, sizeof(struct utsname));

  return 0;
}

char* k_getcwd(char* buf, size_t size)
{
  UNUSED(size);

  if (buf != NULL) {
    strncpy(buf, "/", 2);
  }

  return "/";
}

static void* heap = NULL;
static uint8_t heap_inc = 1;
static uintptr_t curr_brk = 0;

uintptr_t k_brk(uintptr_t addr)
{
  SYS_DEBUG("curr_brk=%p addr=%p", curr_brk, addr);

  if (addr == 0) {
    if (heap == NULL) {
      SYS_DEBUG("%s", "initializing heap");
      heap = malloc(PAGE_SIZE * HEAP_PAGES);
      curr_brk = (uintptr_t)heap;
    }

    return curr_brk;
  }

  curr_brk = addr;

  return curr_brk;
}

void* k_mmap(void* addr,
             size_t length,
             int prot,
             int flags,
             int fd,
             off_t offset)
{
  MAYBE_UNUSED(length);
  MAYBE_UNUSED(prot);
  MAYBE_UNUSED(flags);
  MAYBE_UNUSED(fd);
  MAYBE_UNUSED(offset);

  SYS_DEBUG("addr=%p length=%d prot=%d flags=%d fd=%d offset=%d",
            addr,
            length,
            prot,
            flags,
            fd,
            offset);

  if (addr == NULL) {
    if (heap == NULL) {
      SYS_DEBUG("%s", "initializing heap");
      heap = malloc(PAGE_SIZE * HEAP_PAGES);
      curr_brk = (uintptr_t)heap;

      return heap;
    }

    return &heap[PAGE_SIZE * heap_inc++];
  }

  return addr;
}

int k_return_zero()
{
#ifdef __x86_64__
  uint64_t rax = 0;
  // TODO: make it arch-specific.
  __asm__("mov %%rax, %0" : "=r"(rax) : /* no input */);
  DEBUG("called syscall stub for %s (0x%02X)", syscall_names[rax], rax);
#endif

  return 0;
}

int k_ioctl(int fd, int request, void* ptr)
{
  MAYBE_UNUSED(fd);
  MAYBE_UNUSED(request);
  MAYBE_UNUSED(ptr);

  SYS_DEBUG("fd=%d request=%d ptr=%p", fd, request, ptr);

  return 0;
}

int k_writev(int fd, struct iovec* iov, int iovcnt)
{
  SYS_DEBUG("fd=%d iovcnt=%d", fd, iovcnt);

  int retval = 0;
  for (int i = 0; i < iovcnt; i++) {
    int rv = k_write(fd, (void*)iov[i].base, iov[i].len);

    if (rv < 0) {
      return rv;
    }

    retval += rv;
  }

  return retval;
}

int k_arch_prctl(int code, uintptr_t addr)
{
  SYS_DEBUG("code=%d addr=%p", code, addr);

#ifdef __x86_64__
  if (code != SET_FSBASE) {
    return -EINVAL;
  }

  __asm__("wrfsbase %0" ::"r"(addr));

  return 0;
#else
  UNUSED(code);
  UNUSED(addr);

  return -EINVAL;
#endif
}

int k_not_implemented()
{
  uint64_t num = 0;
  MAYBE_UNUSED(num);

#ifdef __x86_64__
  __asm__("mov %%rax, %0" : "=r"(num) : /* no input */);
#elif __aarch64__
  __asm__("mov x8, %0" : "=r"(num) : /* no input */);
#endif

  DEBUG("called unimplemented syscall %s (0x%02X)", syscall_names[num], num);

  return -ENOSYS;
}

void syscall_init()
{
  INFO("%s", "sys: initialize syscalls");

  MAYBE_UNUSED(syscall_names);

  syscall_handlers[SYSCALL_TEST] = (syscall_ptr_t)k_test;
  syscall_handlers[SYSCALL_WRITE] = (syscall_ptr_t)k_write;
  syscall_handlers[SYSCALL_READ] = (syscall_ptr_t)k_read;
  syscall_handlers[SYSCALL_GETTIMEOFDAY] = (syscall_ptr_t)k_gettimeofday;
#ifndef __aarch64__
  syscall_handlers[SYSCALL_OPEN] = (syscall_ptr_t)k_open;
#endif
  syscall_handlers[SYSCALL_CLOSE] = (syscall_ptr_t)k_close;
  syscall_handlers[SYSCALL_REBOOT] = (syscall_ptr_t)k_reboot;
  syscall_handlers[SYSCALL_FSTAT] = (syscall_ptr_t)k_fstat;
  syscall_handlers[SYSCALL_LSEEK] = (syscall_ptr_t)k_lseek;
  syscall_handlers[SYSCALL_SOCKET] = (syscall_ptr_t)k_socket;
  syscall_handlers[SYSCALL_SENDTO] = (syscall_ptr_t)k_sendto;
  syscall_handlers[SYSCALL_RECVFROM] = (syscall_ptr_t)k_recvfrom;
  syscall_handlers[SYSCALL_GETHOSTBYNAME2] = (syscall_ptr_t)k_gethostbyname2;
  syscall_handlers[SYSCALL_EXECV] = (syscall_ptr_t)k_execv;
  syscall_handlers[SYSCALL_GETPID] = (syscall_ptr_t)k_getpid;
  syscall_handlers[SYSCALL_EXIT] = (syscall_ptr_t)k_exit;
  syscall_handlers[SYSCALL_OPENAT] = (syscall_ptr_t)k_openat;

#ifdef SYSCALL_IOCTL
  syscall_handlers[SYSCALL_IOCTL] = (syscall_ptr_t)k_ioctl;
#endif
#ifdef SYSCALL_WRITEV
  syscall_handlers[SYSCALL_WRITEV] = (syscall_ptr_t)k_writev;
#endif
#ifdef SYSCALL_DUP2
  syscall_handlers[SYSCALL_DUP2] = (syscall_ptr_t)k_dup2;
#endif
#ifdef SYSCALL_GETEUID
  // TODO: Implement handler for `geteuid`.
  syscall_handlers[SYSCALL_GETEUID] = (syscall_ptr_t)k_return_zero;
  syscall_names[SYSCALL_GETEUID] = "geteuid";
#endif
#ifdef SYSCALL_ARCH_PRCTL
  syscall_handlers[SYSCALL_ARCH_PRCTL] = (syscall_ptr_t)k_arch_prctl;
#endif
#ifdef SYSCALL_SET_TID_ADDR
  // TODO: Implement handler for `set_tid_addr`.
  syscall_handlers[SYSCALL_SET_TID_ADDR] = (syscall_ptr_t)k_return_zero;
  syscall_names[SYSCALL_SET_TID_ADDR] = "set_tid_address";
#endif
#ifdef SYSCALL_EXIT_GROUP
  syscall_handlers[SYSCALL_EXIT_GROUP] = (syscall_ptr_t)k_exit;
#endif
#ifdef SYSCALL_BRK
  syscall_handlers[SYSCALL_BRK] = (syscall_ptr_t)k_brk;
#endif
#ifdef SYSCALL_POLL
  syscall_handlers[SYSCALL_POLL] = (syscall_ptr_t)k_poll;
#endif
#ifdef SYSCALL_MMAP
  syscall_handlers[SYSCALL_MMAP] = (syscall_ptr_t)k_mmap;
#endif
#ifdef SYSCALL_RT_SIGPROCMASK
  // TODO: Implement handler for `rt_sigprocmask`.
  syscall_handlers[SYSCALL_RT_SIGPROCMASK] = (syscall_ptr_t)k_return_zero;
  syscall_names[SYSCALL_RT_SIGPROCMASK] = "rt_sigprocmask";
#endif
#ifdef SYSCALL_NANOSLEEP
  // TODO: Implement handler for `nanosleep`.
  syscall_handlers[SYSCALL_NANOSLEEP] = (syscall_ptr_t)k_return_zero;
  syscall_names[SYSCALL_NANOSLEEP] = "nanosleep";
#endif
#ifdef SYSCALL_CONNECT
  syscall_handlers[SYSCALL_CONNECT] = (syscall_ptr_t)k_connect;
#endif
#ifdef SYSCALL_BIND
  // TODO: Implement handler for `bind`.
  syscall_handlers[SYSCALL_BIND] = (syscall_ptr_t)k_return_zero;
  syscall_names[SYSCALL_BIND] = "bind";
#endif
#ifdef SYSCALL_GETSOCKNAME
  syscall_handlers[SYSCALL_GETSOCKNAME] = (syscall_ptr_t)k_getsockname;
#endif
#ifdef SYSCALL_SETSOCKOPT
  // TODO: Implement handler for `setsockopt`.
  syscall_handlers[SYSCALL_SETSOCKOPT] = (syscall_ptr_t)k_return_zero;
  syscall_names[SYSCALL_SETSOCKOPT] = "setsockopt";
#endif
#ifdef SYSCALL_UNAME
  syscall_handlers[SYSCALL_UNAME] = (syscall_ptr_t)k_uname;
#endif
#ifdef SYSCALL_GETCWD
  syscall_handlers[SYSCALL_GETCWD] = (syscall_ptr_t)k_getcwd;
#endif
#ifdef SYSCALL_SETUID
  // TODO: Implement handler for `setuid`.
  syscall_handlers[SYSCALL_SETUID] = (syscall_ptr_t)k_return_zero;
  syscall_names[SYSCALL_SETUID] = "setuid";
#endif
#ifdef SYSCALL_SETGID
  // TODO: Implement handler for `setgid`.
  syscall_handlers[SYSCALL_SETGID] = (syscall_ptr_t)k_return_zero;
  syscall_names[SYSCALL_SETGID] = "setgid";
#endif
#ifdef SYSCALL_FCNTL
  // TODO: Implement handler for `fcntl`.
  syscall_handlers[SYSCALL_FCNTL] = (syscall_ptr_t)k_return_zero;
  syscall_names[SYSCALL_FCNTL] = "fcntl";
#endif
#ifdef SYSCALL_MUNMAP
  // TODO: Implement handler for `munmap`.
  syscall_handlers[SYSCALL_MUNMAP] = (syscall_ptr_t)k_return_zero;
  syscall_names[SYSCALL_MUNMAP] = "munmap";
#endif
#ifdef SYSCALL_RT_SIGACTION
  // TODO: Implement handler for `rt_sigaction`.
  syscall_handlers[SYSCALL_RT_SIGACTION] = (syscall_ptr_t)k_return_zero;
  syscall_names[SYSCALL_RT_SIGACTION] = "rt_sigaction";
#endif

  arch_syscall_init();
}
