/*

This program will allocate NB_PAGES pages of memory and fill them with 0xFF bytes.
Then, it will make the memory read-only by calling the mprotect syscall.
Finally, it will enter an infinite loop to make it easier to track the memory usage.

Compile it with: gcc syscalls.s wrapper.c main.c -nostdlib -o mmap_tester

Run it with: ./mmap_tester

This program is a simple example of how to use the mmap/munmap/mprotect system calls
without using the libc. It is useful to test your implementation of your module, more
specifically the number of identical pages.

You can change the number of pages by changing the NB_PAGES macro. In addition, you can
modify it to create several groups of identical pages.

You can also have an idea of the total memory consumption by parsing the smaps_rollup file:
- This is not an exact match but an upper bound.
- This is only representative for statically-linked programs.

Example: cat /proc/$(pidof mmap_tester)/smaps_rollup|grep "Pss:"|head -n 1

*/

#define NB_PAGES 10000  // The number of pages that you want (default 10000)
#define PAGESIZE 0x1000 // 4KB - 4096 bytes (default size of a page; DO NOT EDIT)

// Used for mmap/munmap/mprotect system calls
#define NULL 0x0

#define PROT_NONE        0x0
#define PROT_READ        0x1
#define PROT_WRITE       0x2
#define PROT_EXEC        0x4

#define MAP_PRIVATE      0x2
#define MAP_ANONYMOUS    0x20
#define PROT (PROT_READ | PROT_WRITE | PROT_EXEC)
#define FLAGS (MAP_PRIVATE | MAP_ANONYMOUS)

// Basic wrapper to mmap/munmap/mprotect system calls
extern void *mmap(void *addr, int len, int prot, int flags, int fd, int offset);
extern int munmap(void *addr, int len);
extern int mprotect(void *addr, int len, int prot);

// Basic memset implementation
static void *memset(void *s, int c, int n) {
  char *s_str = (char *)s;
  for (int i = 0; i < n; i++)
    s_str[i] = c;
  return s;
}

// Simple main function
int main() {
  const int length = PAGESIZE * NB_PAGES;
  char *addr = mmap(NULL, length, PROT, FLAGS, -1, 0);

  // on-demand paging filled with 0xFF bytes
  memset(addr, 0xFF, length);
  // make read-only by calling the mprotect syscall
  mprotect(addr, length, PROT_READ);
  // infinite loop for easy tracking
  while(1);

  munmap(addr, length);

  return 0;
}

// start function (no libc)
__attribute__((force_align_arg_pointer))
void _start() {
  main();
  // exit syscall
  asm("movl $1,%eax;"
        "xorl %ebx,%ebx;"
        "int  $0x80"
    );
    __builtin_unreachable();
}
