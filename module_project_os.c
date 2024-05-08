#include <linux/fs.h>        // file operations
#include <linux/proc_fs.h>   // proc_create, proc_ops
#include <linux/uaccess.h>   // copy_from_user, copy_to_user
#include <linux/init.h>      // kernel initialization
#include <linux/seq_file.h>  // seq_read, seq_lseek, single_open, single_release
#include <linux/module.h>    // all modules need this
#include <linux/slab.h>      // memory allocation (kmalloc/kzalloc)
#include <linux/kernel.h>    // kernel logging
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/sched/signal.h>
#include <linux/sched/mm.h>
#include <linux/memory.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>

#define DEV_NAME "memory_info"  // name of the proc entry
#define MAX_PIDS 1000
#define MAX_NAME_LENGTH 16      // maximum length of a process name is limited at 16 characters

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Group08");
MODULE_DESCRIPTION("Kernel module for tracking memory usage of processes");

static char *message = NULL;

// Define a structure to store memory information for each set of processes
struct process_memory_info {
    char name[MAX_NAME_LENGTH + 1]; // Additional space for null terminator: need to test this
    int *pids;
    int pid_count;
    unsigned long nb_total_pages;
    unsigned long nb_valid_pages;
    unsigned long nb_invalid_pages;
    unsigned long nb_shareable_pages;
    unsigned long nb_group;
    struct hlist_node node;
};
static DEFINE_HASHTABLE(process_memory_hash, 8); //what number to put ? a power of 2
//static DEFINE_SPINLOCK(process_memory_hash_lock);

// Function to calculate hash value for a string
static inline unsigned int hash_str(const char *str)
{
    return jhash(str, strlen(str), 0);
}

// Function to populate the data structure with memory information for running processes
static void populate_process_memory_info(void) {
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    struct process_memory_info *info;
    struct process_memory_info *existing_info;

    // Iterate through each process
    for_each_process(task) {
        unsigned long prev_start = 0;
        unsigned long prev_end = 0;
        // Allocate memory for the info structure
        info = kmalloc(sizeof(*info), GFP_KERNEL);
        if (!info) {
            printk(KERN_ERR "Failed to allocate memory for process info\n");
            return;
        }

        // Initialize info structure
        strncpy(info->name, task->comm, MAX_NAME_LENGTH);
        info->name[MAX_NAME_LENGTH] = '\0'; // Ensure null termination

        //NEED to change this !
        info->pids = kmalloc(MAX_PIDS * sizeof(int), GFP_KERNEL);
        if (!info->pids) {
            printk(KERN_ERR "Failed to allocate memory for PIDs\n");
            kfree(info); // Free allocated memory if PID array allocation fails
            continue;
        }
        info->pids[0] = task->pid; // Store PID
        info->pid_count = 1;       // Update PID count
        info->nb_total_pages = 0;
        info->nb_valid_pages = 0;
        info->nb_invalid_pages = 0;
        info->nb_shareable_pages = 0;
        info->nb_group = 0;

        // Get task's memory management struct (mm)
        mm = get_task_mm(task);
        // ecampus: "Processes with a NULL task->mm struct, must not be displayed."
        if (!mm) {
            printk(KERN_ERR "Failed to get mm_struct for process %d\n", task->pid);
            kfree(info->pids); // Free allocated memory for PIDs
            kfree(info); // Free allocated memory if mm_struct is missing
            continue;
        } else {
            printk(KERN_INFO "Getting mm_struct for process %d suceeded\n", task->pid);
        }

        // Gather memory usage information (replace with functions based on your kernel version)
        //info->nb_total_pages = get_mm_total_rss(mm); // Total resident set size
        //info->nb_valid_pages = get_mm_rss(mm);             // Resident set size (excluding swap)

        //WTF: need to understand
        // Iterate over each VMA of the process
        for (vma = mm->mmap; vma; vma = vma->vm_next) {
            unsigned long start = vma->vm_start;
            unsigned long end = vma->vm_end;
            unsigned long size = end - start;
            info->nb_total_pages += size >> PAGE_SHIFT;
            if (vma->vm_flags & VM_SOFTDIRTY)
                info->nb_valid_pages += size >> PAGE_SHIFT;
            else
                info->nb_invalid_pages += size >> PAGE_SHIFT;
            if ((vma->vm_flags & VM_SHARED) && !(vma->vm_flags & VM_WRITE)) {
                if (start == prev_start && end == prev_end) {
                    info->nb_shareable_pages += size >> PAGE_SHIFT;
                    info->nb_group++;
                }
            }
            prev_start = start;
            prev_end = end;
        }

        // Check if the entry already exists in the hash table
        hash_for_each_possible(process_memory_hash, existing_info, node, hash_str(info->name)) {
            if (strncmp(existing_info->name, info->name, MAX_NAME_LENGTH) == 0) {
                // Entry already exists, update it
                info->pid_count = existing_info->pid_count + 1;
                memcpy(existing_info->pids, info->pids, sizeof(int) * existing_info->pid_count);
                existing_info->nb_total_pages += info->nb_total_pages;
                existing_info->nb_valid_pages += info->nb_valid_pages;
                existing_info->nb_invalid_pages += info->nb_invalid_pages;
                existing_info->nb_shareable_pages += info->nb_shareable_pages;
                existing_info->nb_group += info->nb_group;
                kfree(info->pids);
                kfree(info);
                goto next_process;
            }
        }

        // Entry doesn't exist, add it to the hash table
        hash_add(process_memory_hash, &info->node, hash_str(info->name));

    next_process:
        continue;
    }
}

/*void print_process_info(void) {
    struct task_struct *task;

    for_each_process(task) {
        printk(KERN_INFO "Process Name: %s (PID: %d)\n", task->comm, task->pid);
    }
}*/

// Function to free resources associated with DS
static void free_process_memory_info(void) {
    struct process_memory_info *info;
    struct hlist_node *tmp;
    unsigned int bkt;
    printk(KERN_INFO "free_process_memory_info\n");

    // Iterate through the hash table and free memory for each entry
    hash_for_each_safe(process_memory_hash, bkt, tmp, info, node) {
        printk(KERN_INFO "free_process_memory_info: process\n");
        // Free any allocated memory for the entry
        hash_del(&info->node);
        kfree(info->pids);
        kfree(info);
        printk(KERN_INFO "free_process_memory_info: end process\n");
    }
}

// Function to format memory information of a specific process node
static char *format_process_memory_info(struct process_memory_info *info) {
    char *output_buffer = NULL;
    char *ptr = NULL;
    size_t buffer_size = 0;
    int i;
    printk(KERN_INFO "Inside format_process_memory_info for process %d\n", info->pids[0]);

    // Calculate the required buffer size
    buffer_size += snprintf(NULL, 0, "%s, total: %lu, valid: %lu, invalid: %lu, maybeshared: %lu, nbgroup: %lu, pid(#pid):",
                            info->name, info->nb_total_pages, info->nb_valid_pages, info->nb_invalid_pages,
                            info->nb_shareable_pages, info->nb_group);
    for (i = 0; i < info->pid_count; ++i) {
        buffer_size += snprintf(NULL, 0, " %d", info->pids[i]);
    }
    buffer_size += snprintf(NULL, 0, "\n");
    printk(KERN_INFO "- buffer size = %zu\n", buffer_size);

    // Allocate memory for the output buffer
    output_buffer = kmalloc(buffer_size + 1, GFP_KERNEL);
    if (!output_buffer) {
        return NULL;
    }

    // Format the output
    ptr = output_buffer;
    ptr += snprintf(ptr, buffer_size + 1, "%s, total: %lu, valid: %lu, invalid: %lu, maybeshared: %lu, nbgroup: %lu, pid(#pid):",
                    info->name, info->nb_total_pages, info->nb_valid_pages, info->nb_invalid_pages,
                    info->nb_shareable_pages, info->nb_group);
    for (i = 0; i < info->pid_count; ++i) {
        ptr += snprintf(ptr, buffer_size +1 - (ptr - output_buffer), " %d", info->pids[i]);
    }
    ptr += snprintf(ptr, buffer_size +1 - (ptr - output_buffer), "\n");
    printk(KERN_INFO "Formatted output: %s\n", output_buffer);
    printk(KERN_INFO "- end format_process_memory_info\n");

    return output_buffer;
}

// this function writes a message to the pseudo file system
static ssize_t write_msg(struct file *file, const char __user *buff, size_t cnt, loff_t *f_pos) {
    char *command = NULL;
    char *output_buffer = NULL;
    size_t buffer_size = 0;
    char *argument = NULL;
    ssize_t ret = 0;

    // allocate memory, (size and flag) - flag: type of memory (kernel memory)
    char *tmp = kzalloc(cnt + 1, GFP_KERNEL);
    if (!tmp) {
        return -ENOMEM;
    }

    // copy data from user space to kernel space by using copy_from_user
    if (copy_from_user(tmp, buff, cnt)) {
        kfree(tmp);
        return -EFAULT;
    }

    // Tokenize the input buffer to extract command and argument
    command = strsep(&tmp, " \n");
    if (!command) {
        ret = -EINVAL; // Malformed command
        goto out;
    }

    if (strcmp(command, "RESET") == 0) {
        printk(KERN_INFO "Read RESET\n");
        // Reset the in-memory data structure
        free_process_memory_info();
        // Populate it with process information
        populate_process_memory_info();
        message = "[SUCCESS]\n";
        ret = strlen(message);
    } else if (strcmp(command, "ALL") == 0) {
        // Display memory information of all processes
        struct process_memory_info *info;
        //struct hlist_node *node;
        unsigned int bkt;
        printk(KERN_INFO "Read ALL\n");

        // Iterate through the hash table and format each process node
        hash_for_each(process_memory_hash, bkt, info, node) {
            char *formatted_info = format_process_memory_info(info);
            if (!formatted_info) {
                ret = -ENOMEM;
                goto out;
            }
            buffer_size += strlen(formatted_info);
            output_buffer = krealloc(output_buffer, buffer_size + 1, GFP_KERNEL);
            if (!output_buffer) {
                ret = -ENOMEM;
                kfree(formatted_info);
                goto out;
            }
            strcat(output_buffer, formatted_info);
            strcat(output_buffer, "\n"); // Add a newline between each process info
            kfree(formatted_info);
        }
        message = output_buffer;
        printk(KERN_INFO "end ALL - message = %s\n", message);
        ret = strlen(message);
    } else if (strncmp(command, "FILTER|", 7) == 0) {
        printk(KERN_INFO "Read FILTER|\n");
        argument = command + 7;
    } else if (strncmp(command, "DEL|", 4) == 0) {
        printk(KERN_INFO "Read DEL|\n");
        argument = command + 4;
    } else {
        ret = -EINVAL; // Unknown command
        printk(KERN_INFO "Read ERROR IN COMMAND\n");
        goto out;
    }

out:
    // Cleanup in case of error
    kfree(tmp);
    //kfree(command);
    kfree(output_buffer);
    return ret;
}

// this function reads a message from the pseudo file system via the seq_printf function
static int show_the_proc(struct seq_file *a, void *v) {
    seq_printf(a,"%s\n",message);
    return 0;
}

// this function opens the proc entry by calling the show_the_proc function
static int open_the_proc(struct inode *inode, struct file *file) {
    return single_open(file, show_the_proc, NULL);
}

/*-----------------------------------------------------------------------*/
// Structure that associates a set of function pointers (e.g., device_open)
// that implement the corresponding file operations (e.g., open).
/*-----------------------------------------------------------------------*/
static struct file_operations new_fops={ //defined in linux/fs.h
    .owner = THIS_MODULE,
    .open = open_the_proc,   //open callback
    .release = single_release,
    .read = seq_read,        //read
    .write = write_msg,      //write callback
    .llseek = seq_lseek,
};

// Module initialization function
static int __init module_start(void) {
    // create proc entry with read/write functionality
    struct proc_dir_entry *entry = proc_create(DEV_NAME, 0777, NULL, &new_fops);
    if(!entry) {
        return -1;
    } //else
    printk(KERN_INFO "Memory information for running processes.\n");
    populate_process_memory_info();
    //print_process_info();
    printk(KERN_INFO "Init Module [OK]\n");
    return 0;
}

// Module exit function
static void __exit module_stop(void) {
    printk(KERN_INFO "exit");
    free_process_memory_info();
    printk(KERN_INFO "Memory information data structure freed.\n");
    // remove proc entry
    remove_proc_entry(DEV_NAME, NULL);
    printk(KERN_INFO "Exit Module [OK]\n");
}

module_init(module_start);
module_exit(module_stop);
