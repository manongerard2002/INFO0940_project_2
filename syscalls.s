.global sys_mmap
.global sys_munmap
.global sys_mprotect
sys_mmap:
  pushl %ebp
  movl %esp, %ebp
  movl 8(%ebp), %ebx
  movl $90, %eax
  int $128
  popl %ebp
  ret

sys_munmap:
  pushl %ebp
  movl %esp, %ebp
  movl 8(%ebp), %ecx
  movl 12(%ebp), %ebx
  movl $91, %eax
  int $128
  popl %ebp
  ret

sys_mprotect:
  pushl %ebp
  movl %esp, %ebp
  movl 8(%ebp), %ecx
  movl 12(%ebp), %ebx
  movl 16(%ebp), %edx
  movl $92, %eax
  int $128
  popl %ebp
  ret