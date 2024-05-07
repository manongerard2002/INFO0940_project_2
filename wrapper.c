// x86 Linux interface
struct mmap_arg_struct {
  unsigned long addr;
  unsigned long len;
  unsigned long prot;
  unsigned long flags;
  unsigned long fd;
  unsigned long offset;
};

extern void *sys_mmap(struct mmap_arg_struct *args);
extern int sys_munmap(void *addr, int len);
extern int sys_mprotect(void *addr, int len, int prot);

// mprotect wrapper
int mprotect(void *addr, int len, int prot) {
  return sys_mprotect(addr, len, prot);
}

// mmap wrapper
void *mmap(void *addr, int len, int prot, int flags, int fd, int offset) {
  struct mmap_arg_struct args;
  args.addr = (unsigned long) addr;
  args.len = len;
  args.prot = prot;
  args.flags = flags;
  args.fd = fd;
  args.offset = offset;

  return sys_mmap(&args);
}

// munmap wrapper
int munmap(void *addr, int len) {
  return sys_munmap(addr, len);
}

