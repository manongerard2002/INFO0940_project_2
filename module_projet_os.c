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
#include <linux/mm_types.h>
#include <linux/pagemap.h>
#include <linux/rcupdate.h>

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
        printk(KERN_ERR "Error: NULL pointer passed to print_process_memory_info");
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

    printk(KERN_INFO "---------------------------------------");
    printk(KERN_INFO "Printing Hash Table:");

    // Iterate over each possible entry in the hash table
    hash_for_each(process_memory_hashlist, bkt, info, hlist_node)
    {
        print_process_memory_info(info);
    }
    printk(KERN_INFO "---------------------------------------");
}

static unsigned long count_valid_pages(struct mm_struct *mm)
{
    unsigned long valid_pages = 0;
    struct vm_area_struct *vma;
    unsigned long address;

    if (!mm)
    {
        return 0;
    }

    // Iterate over each virtual memory area (VMA) in the process's memory map
    for (vma = mm->mmap; vma; vma = vma->vm_next)
    {
        // Iterate over each page in the VMA
        for (address = vma->vm_start; address < vma->vm_end; address += PAGE_SIZE)
        {
            pgd_t *pgd;
        	p4d_t *p4d;
        	pud_t *pud;
        	pmd_t *pmd;
        	pte_t *ptep;

        	pgd = pgd_offset(mm, address);
        	if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))
        		continue;

        	p4d = p4d_offset(pgd, address);
        	if (p4d_none(*p4d) || unlikely(p4d_bad(*p4d)))
        		continue;

        	pud = pud_offset(p4d, address);
        	if (pud_none(*pud) || unlikely(pud_bad(*pud)))
        		continue;

        	pmd = pmd_offset(pud, address);
        	if (pmd_none(*pmd) || unlikely(pmd_bad(*pmd)))
        		continue;

            ptep = pte_offset_map(pmd, address);
            if (!ptep)
                continue;

        	if (pte_present(*ptep))
            {
                valid_pages++;
            }
        }
    }
    return valid_pages;
}

// Function to calculate hash value for a page's content
// based on calc_checksum from mm/ksm.c
static inline unsigned long hash_page_content(struct page *page)
{
    unsigned long hash = 0;
    void *addr = kmap_atomic(page);
    hash = jhash2(addr, PAGE_SIZE / sizeof(unsigned long), 17);
    kunmap_atomic(addr);
    return hash;
}

// Function to count shareable pages in a process's memory map
static unsigned long count_shareable_pages(struct mm_struct *mm)
{
    unsigned long shareable_pages = 0;
    struct vm_area_struct *vma;
    unsigned long address;
    struct page *page;
    unsigned long hash;
    unsigned long prev_hash = 0;
    bool first_page = true;

    if (!mm)
    {
        return 0;
    }

    // Iterate over each virtual memory area (VMA) in the process's memory map
    for (vma = mm->mmap; vma; vma = vma->vm_next)
    {
        // Iterate over each page in the VMA
        for (address = vma->vm_start; address < vma->vm_end; address += PAGE_SIZE)
        {
            // Get the page corresponding to the current address
            page = vmalloc_to_page((void*) address);
            if (!page)
                continue;

            // Calculate the hash value for the page's content
            hash = hash_page_content(page);

            // Check if the current page's content matches the previous page's content
            if (!first_page && hash == prev_hash)
            {
                // Found a shareable page
                shareable_pages++;
            }

            // Update the previous hash for the next iteration
            prev_hash = hash;
            first_page = false;
        }
    }

    return shareable_pages;
}

// Function to populate the data structure with memory information for running processes
static ssize_t populate_process_memory_hashlist(void)
{
    ssize_t ret = 0;
    struct task_struct *task;
    struct process_memory_info *info, *existing_info;
    struct mm_struct *mm;
    struct pid_entry *new_pid_entry;
    unsigned long valid_pages, shareable_pages;

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

        valid_pages = count_valid_pages(mm);
        shareable_pages = count_shareable_pages(mm);

        // Check if the entry already exists in the hash table
        hash_for_each_possible(process_memory_hashlist, existing_info, hlist_node, hash_str(task->comm))
        {
            if (strncmp(existing_info->name, task->comm, MAX_NAME_LENGTH) == 0)
            {
                // Entry already exists, update it
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
                existing_info->nb_valid_pages += valid_pages;
                existing_info->nb_invalid_pages += mm->total_vm - valid_pages;
                existing_info->nb_shareable_pages += shareable_pages;
                existing_info->nb_group += 0;
                goto next_process;
            }
        }

        // Entry doesn't exist, allocate memory for the info structure
        info = kmalloc(sizeof(*info), GFP_KERNEL);
        if (!info)
        {
            printk(KERN_ERR "[ERROR]: Failed to allocate memory for process info");
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
            printk(KERN_ERR "[ERROR]: Failed to allocate memory for PIDs");
            kfree(info); // Free allocated memory if PID entry allocation fails
            ret = -ENOMEM;
            goto out_populate;
        }
        new_pid_entry->pid = task->pid;
        list_add_tail(&new_pid_entry->list_node, &info->pids);
        info->pid_count = 1;
        info->nb_total_pages = mm->total_vm;
        info->nb_valid_pages = valid_pages;
        info->nb_invalid_pages = mm->total_vm - valid_pages;
        info->nb_shareable_pages = shareable_pages;
        info->nb_group = 0;

        // Add the new entry to the hashtable
        hash_add(process_memory_hashlist, &info->hlist_node, hash_str(task->comm));

    next_process:
        continue;
    }

out_populate:
    return ret;
}

static void free_process_memory_info(struct process_memory_info *info)
{
    struct pid_entry *pid_entry, *pid_tmp;
    if (!info)
    {
        printk(KERN_ERR "Error: NULL pointer passed to print_process_memory_info");
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
        printk(KERN_ERR "[ERROR]: Null pointer passed to calculate_buffer_size");
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
        printk(KERN_ERR "[ERROR]: Null pointer passed to format_process_memory_info");
        return NULL;
    }

    // Calculate the total length of the message
    buffer_size = calculate_buffer_size(info);

    // Allocate memory for the message
    output_buffer = kmalloc(buffer_size + 1, GFP_KERNEL); //+1 for '\0'
    if (!output_buffer)
    {
        printk(KERN_ERR "[ERROR]: Memory allocation error");
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
        printk(KERN_ERR "[ERROR]: Memory allocation error");
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
        printk(KERN_ERR "[ERROR]: Memory allocation error");
        ret = -ENOMEM;
        goto out_write_msg;
    }

    // copy data from user space to kernel space by using copy_from_user
    if (copy_from_user(tmp, buff, cnt))
    {
        printk(KERN_ERR "[ERROR]: Bad address");
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
        message = kstrdup("[SUCCESS]", GFP_KERNEL);
        if (!message)
        {
            printk(KERN_ERR "[ERROR]: Memory allocation error");
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
            message = kstrdup("[ERROR]: No such process", GFP_KERNEL);
            printk(KERN_ERR "[ERROR]: No such process");
            ret = -ESRCH; //EINVAL; lequel ?
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
            message = kstrdup("[ERROR]: No such process", GFP_KERNEL);
            printk(KERN_ERR "[ERROR]: No such process");
            ret = -ESRCH; //EINVAL; lequel ?
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
            message = kstrdup("[ERROR]: No such process", GFP_KERNEL);
            printk(KERN_ERR "[ERROR]: No such process");
            ret = -ESRCH; //EINVAL; lequel ?
            goto out_free_tmp_write_msg;
        }
        hash_for_each_possible(process_memory_hashlist, existing_info, hlist_node, hash_str(name))
        {
            if (strncmp(existing_info->name, name, MAX_NAME_LENGTH) == 0)
            {
                free_process_memory_info(existing_info);
                message = kstrdup("[SUCCESS]", GFP_KERNEL);
                if (!message)
                {
                    printk(KERN_ERR "[ERROR]: Memory allocation error");
                    ret = -ENOMEM;
                }
                goto out_free_tmp_write_msg;
            }
        }
        if (!message)
        {
            message = kstrdup("[ERROR]: No such process", GFP_KERNEL);
            printk(KERN_ERR "[ERROR]: No such process");
            ret = -ESRCH;
            goto out_free_tmp_write_msg;
        }
    }
    else
    {
        message = kstrdup("[ERROR]: Invalid argument", GFP_KERNEL);
        printk(KERN_ERR "[ERROR]: Invalid argument");
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
        printk(KERN_ERR "[ERROR]: Memory allocation error");
        return -ENOMEM;
    }
    res = populate_process_memory_hashlist();
    return res;
}

// Module exit function
static void __exit module_stop(void)
{
    if (message)
    {
        kfree(message);
    }
    free_process_memory_hashlist();
    // remove proc entry
    remove_proc_entry(DEV_NAME, NULL);
}

module_init(module_start);
module_exit(module_stop);
