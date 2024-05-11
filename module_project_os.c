#include <linux/fs.h>       // file operations
#include <linux/proc_fs.h>  // proc_create, proc_ops
#include <linux/uaccess.h>  // copy_from_user, copy_to_user
#include <linux/init.h>     // kernel initialization
#include <linux/seq_file.h> // seq_read, seq_lseek, single_open, single_release
#include <linux/module.h>   // all modules need this
#include <linux/slab.h>     // memory allocation (kmalloc/kzalloc)
#include <linux/kernel.h>   // kernel logging
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/sched/signal.h>
#include <linux/sched/mm.h>
#include <linux/memory.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/types.h>

#define DEV_NAME "memory_info"  // name of the proc entry
#define MAX_PIDS 1000
#define MAX_NAME_LENGTH 16      // maximum length of a process name is limited at 16 characters

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Group08");
MODULE_DESCRIPTION("Kernel module for tracking memory usage of processes");

static char *message = NULL;

// Define a structure to store the pid of a process
struct pid_entry {
    pid_t pid;
    struct list_head list_node;
};

// Define a structure to store memory information for each set of processes
struct process_memory_info {
    char name[MAX_NAME_LENGTH];
    struct list_head pids;
    int pid_count;
    unsigned long nb_total_pages;
    unsigned long nb_valid_pages;
    unsigned long nb_invalid_pages;
    unsigned long nb_shareable_pages;
    unsigned long nb_group;
    struct hlist_node hlist_node;
};

static DEFINE_HASHTABLE(process_memory_hashlist, 8); //what number to put ? a power of 2

// Function to calculate hash value for a string
static inline unsigned int hash_str(const char *str)
{
    return jhash(str, strlen(str), 0);
}

void print_process_memory_info(struct process_memory_info *info)
{
    struct pid_entry *pid_entry;
    int i = 0;

    if (!info)
    {
        printk(KERN_ERR "Error: NULL pointer passed to print_process_memory_info.\n");
        return;
    }

    printk(KERN_INFO "%s, total: %lu, valid: %lu, invalid: %lu, may_be_shared: %lu, nb_group: %lu, pid(%d): ", 
            info->name, info->nb_total_pages, info->nb_valid_pages, info->nb_invalid_pages, 
            info->nb_shareable_pages, info->nb_group, info->pid_count);

    // Print all the PIDs associated with this process name
    list_for_each_entry(pid_entry, &info->pids, list_node)
    {
        printk(KERN_CONT "%d", pid_entry->pid);
        if (++i < info->pid_count)
        {
            printk(KERN_CONT "; ");
        }
    }
    printk(KERN_CONT "\n");
}

static void print_hash_table(void)
{
    struct process_memory_info *info;
    unsigned int bkt;

    printk(KERN_INFO "---------------------------------------\n");
    printk(KERN_INFO "Printing Hash Table:\n");

    // Iterate over each possible entry in the hash table
    hash_for_each(process_memory_hashlist, bkt, info, hlist_node)
    {
        print_process_memory_info(info);
    }
    printk(KERN_INFO "---------------------------------------\n");
}

// Function to populate the data structure with memory information for running processes
static ssize_t populate_process_memory_hashlist(void)
{
    ssize_t ret = 0;
    struct task_struct *task;
    struct process_memory_info *info, *existing_info;
    struct mm_struct *mm;
    struct pid_entry *new_pid_entry;

    // Iterate through each process
    for_each_process(task)
    {
        // Get task's memory management struct (mm)
        mm = get_task_mm(task);
        if (!mm)
        {
            // Process(es) with no page must be ignored
            continue;
        }

        // Check if the entry already exists in the hash table
        hash_for_each_possible(process_memory_hashlist, existing_info, hlist_node, hash_str(task->comm))
        {
            //printk(KERN_INFO "existing_info->name = %s    task->comm=%s", existing_info->name, task->comm);
            if (strncmp(existing_info->name, task->comm, MAX_NAME_LENGTH) == 0)
            {
                // Entry already exists, update it
                printk(KERN_INFO "Entry %s already exists", task->comm);
                new_pid_entry = kmalloc(sizeof(struct pid_entry), GFP_KERNEL);
                if (!new_pid_entry)
                {
                    // Handle allocation failure
                    ret = -ENOMEM;
                    goto out_populate;
                }
                new_pid_entry->pid = task->pid;
                list_add_tail(&new_pid_entry->list_node, &existing_info->pids);
                existing_info->pid_count++;
                existing_info->nb_total_pages += mm->total_vm;
                /*existing_info->nb_valid_pages += 0;
                existing_info->nb_invalid_pages += 0;
                existing_info->nb_shareable_pages += 2;
                existing_info->nb_group += 0;*/
                goto next_process;
            }
        }

        // Entry doesn't exist, allocate memory for the info structure
        //printk(KERN_INFO "Entry %s doesn't exist", task->comm);
        info = kmalloc(sizeof(*info), GFP_KERNEL);
        if (!info)
        {
            printk(KERN_ERR "[ERROR] Failed to allocate memory for process info\n");
            ret = -ENOMEM;
            goto out_populate;
        }

        // Initialize info structure
        strncpy(info->name, task->comm, MAX_NAME_LENGTH);
        INIT_LIST_HEAD(&info->pids);
        // Add task->pid to info->pids
        new_pid_entry = kmalloc(sizeof(struct pid_entry), GFP_KERNEL);
        if (!new_pid_entry) {
            // Handle allocation failure
            printk(KERN_ERR "[ERROR] Failed to allocate memory for PIDs\n");
            kfree(info); // Free allocated memory if PID entry allocation fails
            ret = -ENOMEM;
            goto out_populate;
        }
        new_pid_entry->pid = task->pid;
        list_add_tail(&new_pid_entry->list_node, &info->pids);
        info->pid_count = 1;
        info->nb_total_pages = mm->total_vm;
        info->nb_valid_pages = 0;
        info->nb_invalid_pages = 0;
        info->nb_shareable_pages = 0;
        info->nb_group = 0;

        // Add the new entry to the hashtable
        hash_add(process_memory_hashlist, &info->hlist_node, hash_str(task->comm));

    next_process:
        continue;
    }
    print_hash_table();

out_populate:
    return ret;
}

static void free_process_memory_info(struct process_memory_info *info)
{
    struct pid_entry *pid_entry, *pid_tmp;
    if (!info)
    {
        printk(KERN_ERR "Error: NULL pointer passed to print_process_memory_info.\n");
        return;
    }

    // Free any allocated memory for the entry
    hash_del(&info->hlist_node);
    list_for_each_entry_safe(pid_entry, pid_tmp, &info->pids, list_node) {
        list_del(&pid_entry->list_node);
        kfree(pid_entry);
    }
    kfree(info);
}

// Function to free resources associated with DS
static void free_process_memory_hashlist(void)
{
    struct process_memory_info *info;
    struct hlist_node *tmp;
    unsigned int bkt;
    struct pid_entry *pid_entry, *pid_tmp;
    // Iterate through the hash table and free memory for each entry
    hash_for_each_safe(process_memory_hashlist, bkt, tmp, info, hlist_node)
    {
        // Free any allocated memory for the entry
        hash_del(&info->hlist_node);
        list_for_each_entry_safe(pid_entry, pid_tmp, &info->pids, list_node) {
            list_del(&pid_entry->list_node);
            kfree(pid_entry);
        }
        kfree(info);
    }
}

static size_t calculate_buffer_size(struct process_memory_info *info)
{
    struct pid_entry *pid_entry;
    size_t buffer_size = 0;
    int i = 0;
    if (!info)
    {
        printk(KERN_ERR "[ERROR] Null pointer passed to calculate_buffer_size.\n");
        return 0;
    }

    // Calculate the total length of the message
    buffer_size += snprintf(NULL, 0, "%s, total: %lu, valid: %lu, invalid: %lu, may_be_shared: %lu, nb_group: %lu, pid(%d): ",
                            info->name, info->nb_total_pages, info->nb_valid_pages, info->nb_invalid_pages,
                            info->nb_shareable_pages, info->nb_group, info->pid_count);
    list_for_each_entry(pid_entry, &info->pids, list_node)
    {
        buffer_size += snprintf(NULL, 0, "%d", pid_entry->pid);
        if (++i < info->pid_count)
        {
            buffer_size += snprintf(NULL, 0, "; ");
        }
    }
    buffer_size += snprintf(NULL, 0, "\n");

    return buffer_size;
}

// Function to generate the message for a given process info
static size_t generate_process_info_message(struct process_memory_info *info, char *output_buffer, size_t buffer_size)
{
    struct pid_entry *pid_entry;
    size_t tmp_buffer_size = 0;
    size_t tmp_size = 0; //need to find better name
    int i = 0;

    // Generate the message for the given process info
    tmp_size = snprintf(output_buffer + tmp_buffer_size, buffer_size, "%s, total: %lu, valid: %lu, invalid: %lu, may_be_shared: %lu, nb_group: %lu, pid(%d): ",
                        info->name, info->nb_total_pages, info->nb_valid_pages, info->nb_invalid_pages,
                        info->nb_shareable_pages, info->nb_group, info->pid_count);
    tmp_buffer_size += tmp_size;
    buffer_size -= tmp_size;

    list_for_each_entry(pid_entry, &info->pids, list_node)
    {
        tmp_size = snprintf(output_buffer + tmp_buffer_size, buffer_size, "%d", pid_entry->pid);
        tmp_buffer_size += tmp_size;
        buffer_size -= tmp_size;
        if (++i < info->pid_count)
        {
            tmp_size = snprintf(output_buffer + tmp_buffer_size, buffer_size, "; ");
            tmp_buffer_size += tmp_size;
            buffer_size -= tmp_size;
        }
    }
    tmp_size = snprintf(output_buffer + tmp_buffer_size, buffer_size, "\n");
    tmp_buffer_size += tmp_size;

    return tmp_buffer_size;
}

// Function to format process memory info for a single process
static char *format_process_memory_info(struct process_memory_info *info)
{
    size_t buffer_size = 0;
    char *output_buffer = NULL;
    if (!info)
    {
        printk(KERN_ERR "[ERROR] Null pointer passed to format_process_memory_info.\n");
        return NULL;
    }

    // Calculate the total length of the message
    buffer_size = calculate_buffer_size(info);

    // Allocate memory for the message
    output_buffer = kmalloc(buffer_size + 1, GFP_KERNEL); //+1 for '\0'
    if (!output_buffer)
    {
        printk(KERN_ERR "[ERROR] Failed to allocate memory for message.\n");
        return NULL;
    }

    // Generate the message for the given process info
    generate_process_info_message(info, output_buffer, buffer_size);

    return output_buffer;
}

// Function to format process memory info for all processes
static char *format_process_memory_info_ALL(void)
{
    struct process_memory_info *info;
    unsigned int bkt;
    size_t buffer_size = 0;
    size_t tmp_buffer_size = 0;
    char *output_buffer = NULL;

    // Calculate the total length of the message
    hash_for_each(process_memory_hashlist, bkt, info, hlist_node)
    {
        buffer_size += calculate_buffer_size(info);
    }

    // Allocate memory for the message
    output_buffer = kmalloc(buffer_size + 1, GFP_KERNEL); //+1 for '\0'
    if (!output_buffer)
    {
        printk(KERN_ERR "[ERROR] Failed to allocate memory for message.\n");
        return NULL;
    }

    // Generate the message for each process info
    hash_for_each(process_memory_hashlist, bkt, info, hlist_node)
    {
        tmp_buffer_size += generate_process_info_message(info, output_buffer + tmp_buffer_size, buffer_size - tmp_buffer_size);
    }

    return output_buffer;
}

// this function writes a message to the pseudo file system
static ssize_t write_msg(struct file *file, const char __user *buff, size_t cnt, loff_t *f_pos)
{
    ssize_t ret = cnt;
    // allocate memory, (size and flag) - flag: type of memory (kernel memory)
    char *tmp = kzalloc(cnt + 1, GFP_KERNEL);
    if (!tmp)
    {
        printk(KERN_ERR "[ERROR] Failed to allocate memory for temporary buffer.\n");
        ret = -ENOMEM;
        goto out_write_msg;
    }

    // copy data from user space to kernel space by using copy_from_user
    if (copy_from_user(tmp, buff, cnt))
    {
        printk(KERN_ERR "[ERROR] Bad address when attempting to copy from user to kernel space.\n");
        ret = -EFAULT;
        goto out_free_tmp_write_msg;
    }

    if (message)
    {
        kfree(message);
        message = NULL;
    }

    if (strcmp(tmp, "RESET\n") == 0)
    {
        ssize_t error;
        // Reset the in-memory data structure
        free_process_memory_hashlist();
        // Populate it with process information
        error = populate_process_memory_hashlist();
        if (error < 0)
        {
            ret = error;
            goto out_free_tmp_write_msg;
        }
        message = kstrdup("[SUCCESS]\n", GFP_KERNEL);
        if (!message)
        {
            printk(KERN_ERR "[ERROR] Failed to allocate memory for RESET message\n");
            ret = -ENOMEM;
            goto out_free_tmp_write_msg;
        }
    }
    else if (strcmp(tmp, "ALL\n") == 0)
    {
        message = format_process_memory_info_ALL();
        if (!message)
        {
            ret = -ENOMEM;
            goto out_free_tmp_write_msg;
        }
    }
    else if (strncmp(tmp, "FILTER|", 7) == 0)
    {
        struct process_memory_info *existing_info;
        char *name = tmp + 7;
        char *newline_ptr = strchr(name, '\n');
        if (newline_ptr)
        {
            *newline_ptr = '\0'; // Remove newline character
        }
        if (strlen(name) > MAX_NAME_LENGTH)
        {
            printk(KERN_ERR "[ERROR] Invalid command, a process name can't be of length higher than %d.\n", MAX_NAME_LENGTH);
            ret = -EINVAL; //-ESRCH : lequel ?
            goto out_free_tmp_write_msg;
        }
        hash_for_each_possible(process_memory_hashlist, existing_info, hlist_node, hash_str(name))
        {
            if (strncmp(existing_info->name, name, MAX_NAME_LENGTH) == 0)
            {
                message = format_process_memory_info(existing_info);
                if (!message)
                {
                    ret = -ENOMEM;
                }
                goto out_free_tmp_write_msg;
            }
        }
        if (!message)
        {
            printk(KERN_ERR "[ERROR] No such process.");
            ret = -ESRCH;
            goto out_free_tmp_write_msg;
        }
    }
    else if (strncmp(tmp, "DEL|", 4) == 0)
    {
        struct process_memory_info *existing_info;
        char *name = tmp + 4;
        char *newline_ptr = strchr(name, '\n');
        if (newline_ptr) {
            *newline_ptr = '\0'; // Remove newline character
        }
        if (strlen(name) > MAX_NAME_LENGTH)
        {
            printk(KERN_ERR "[ERROR] Invalid command, a process name can't be of length higher than %d.\n", MAX_NAME_LENGTH);
            ret = -EINVAL; //-ESRCH : lequel ?
            goto out_free_tmp_write_msg;
        }
        hash_for_each_possible(process_memory_hashlist, existing_info, hlist_node, hash_str(name))
        {
            if (strncmp(existing_info->name, name, MAX_NAME_LENGTH) == 0)
            {
                free_process_memory_info(existing_info);
                message = kstrdup("[SUCCESS]\n", GFP_KERNEL);
                if (!message)
                {
                    printk(KERN_ERR "[ERROR] Failed to allocate memory for RESET message\n");
                    ret = -ENOMEM;
                }
                goto out_free_tmp_write_msg;
            }
        }
        if (!message)
        {
            printk(KERN_ERR "[ERROR] No such process.");
            ret = -ESRCH;
            goto out_free_tmp_write_msg;
        }
    }
    else
    {
        printk(KERN_ERR "[ERROR] Unknown command %s.\n", tmp);
        ret = -EINVAL;
        goto out_free_tmp_write_msg;
    }

out_free_tmp_write_msg:
    kfree(tmp);
out_write_msg:
    return ret;
}

// this function reads a message from the pseudo file system via the seq_printf function
static int show_the_proc(struct seq_file *a, void *v)
{
    seq_printf(a, "%s\n", message);
    return 0;
}

// this function opens the proc entry by calling the show_the_proc function
static int open_the_proc(struct inode *inode, struct file *file)
{
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
static int __init module_start(void)
{
    int res;
    // create proc entry with read/write functionality
    struct proc_dir_entry *entry = proc_create(DEV_NAME, 0777, NULL, &new_fops);
    if (!entry)
    {
        printk(KERN_ERR "[ERROR] Failed to allocate memory for the process entry\n");
        return -ENOMEM;
    }
    res = populate_process_memory_hashlist();
    printk(KERN_INFO "Init Module [OK]\n");
    return res;
}

// Module exit function
static void __exit module_stop(void)
{
    free_process_memory_hashlist();
    print_hash_table();
    // remove proc entry
    remove_proc_entry(DEV_NAME, NULL);
    printk(KERN_INFO "Exit Module [OK]\n");
}

module_init(module_start);
module_exit(module_stop);
