#  Implementing a kernel module

Virtual memory is an abstraction that creates the illusion of a very large main memory. To manage memory efficiently, the kernel divides the virtual address space of a process into various blocks of fixed size (by default 4KB), called pages. When manipulating memory, the kernel first needs to consult the page table which contains the mapping between virtual addresses and physical addresses. In this assignment, you will implement a Linux kernel module able to track memory usage across several processes. Interaction with the kernel will occur through the pseudo file system.

## Score

* The project obtained a score of **19/20**
