obj-m += module_project_os.o
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
load:
	sudo insmod module_project_os.ko
	dmesg
remove:
	sudo rmmod module_project_os.ko
mmap_tester: syscalls.s wrapper.c main.c
	gcc syscalls.s wrapper.c main.c -nostdlib -o mmap_tester
run_mmap_tester: mmap_tester
	./mmap_tester
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
clean-force:
	#rm -f module_project_os.c
	sudo dmesg -C
cmd_reset:
	echo "RESET" > /proc/memory_info && cat /proc/memory_info
	dmesg
cmd_all:
	echo "ALL" > /proc/memory_info && cat /proc/memory_info
	dmesg
cmd_filter:
	echo "FILTER|mmap_tester" > /proc/memory_info && cat /proc/memory_info
	dmesg
cmd_del:
	echo "DEL|mmap_tester" > /proc/memory_info && cat /proc/memory_info
	dmesg
