#include <linux/fs.h>       // file operations
#include <linux/proc_fs.h>  // proc_create, proc_ops
#include <linux/uaccess.h>  // copy_from_user, copy_to_user
#include <linux/init.h>     // kernel initialization
#include <linux/seq_file.h> // seq_read, seq_lseek, single_open, single_release
#include <linux/module.h>   // all modules need this
#include <linux/slab.h>     // memory allocation (kmalloc/kzalloc)
#include <linux/kernel.h>   // kernel logging
#include <linux/list.h>     // linked list
#include <linux/mm.h>       // memory management
#include <linux/sched/signal.h>     // task_struct, for_each_process
#include <linux/sched/mm.h>         // mm_struct, get_task_mm
#include <linux/memory.h>           // struct page
#include <linux/hashtable.h>        // hash table
#include <linux/jhash.h>            // jhash
#include <linux/types.h>            // u32
#include <linux/mm_types.h>         // vm_area_struct
#include <linux/pagemap.h>      
#include <linux/rcupdate.h>
#include <asm/pgtable.h>

#define DEV_NAME "memory_info"  // name of the proc entry
#define MAX_NAME_LENGTH 16      // maximum length of a process name is limited at 16 characters

MODULE_LICENSE("GPL");          // license
MODULE_AUTHOR("Group08");       // authors
MODULE_DESCRIPTION("Kernel module for tracking memory usage of processes"); // description

static char *message = NULL;

/**
 * @struct pid_entry
 * @brief Represents a process ID entry.
 * 
 * This struct contains a process ID and a list node for linking the struct in a list.
 */
struct pid_entry {
    pid_t pid;
    struct list_head list_node;
};


/**
 * @struct process_memory_info
 * @brief Represents information about a process's memory.
 * 
 * This struct contains various fields that provide information about a process's memory.
 * It includes the process name, a list of process IDs, the count of process IDs, the number
 * of total pages, valid pages, invalid pages, shareable pages, and group pages. It also
 * includes a hashlist for counting pages and a hashlist node for linking the struct in a list.
 */
struct process_memory_info {
    char name[MAX_NAME_LENGTH];
    struct list_head pids;
    int pid_count;
    unsigned long nb_total_pages;
    unsigned long nb_valid_pages;
    unsigned long nb_invalid_pages;
    unsigned long nb_shareable_pages;
    unsigned long nb_group;
    struct hlist_head count_hashlist[PAGE_SHIFT]; //what value to put
    struct hlist_node hlist_node;
};


/**
 * @struct hash_count
 * @brief Represents a hash count entry.
 * 
 * This struct contains a hash value, a count, a page, and a hashlist node for linking the struct in a list.
 */
struct hash_count {
    u32 hash;
    unsigned long count;
    struct page *page;
    struct hlist_node hlist_node;
};


/**
 * @brief Hash table for storing process memory information.
 * 
 * This hash table is used to store the process memory information for all running processes.
 */
static DEFINE_HASHTABLE(process_memory_hashlist, 8);


/**
 * @brief Hash function for strings.
 *
 * This function calculates the hash value for a given string.
 *
 * @param str The string for which the hash value needs to be calculated.
 * @return The calculated hash value.
 */
static inline unsigned int hash_str(const char *str)
{
    return jhash(str, strlen(str), 0);
}


/**
 * Calculates the checksum of a given page.
 *
 * @param page The page for which the checksum needs to be calculated.
 * @return The calculated checksum.
 */
static u32 calc_checksum(struct page *page)
{
    u32 checksum;
    void *addr = kmap_atomic(page);
    checksum = jhash2(addr, PAGE_SIZE / 4, 17);
    kunmap_atomic(addr);
    return checksum;
}


/**
 * Compares the contents of two pages in memory.
 *
 * This function compares the contents of two pages in memory, specified by `page1` and `page2`.
 * It uses the `kmap_atomic` function to map the pages to kernel virtual addresses, and then
 * uses the `memcmp` function to compare the contents of the pages. Finally, it uses the
 * `kunmap_atomic` function to unmap the pages.
 *
 * @param page1 The first page to compare.
 * @param page2 The second page to compare.
 * @return 0 if the pages have the same contents, a negative value if `page1` is less than `page2`,
 *         or a positive value if `page1` is greater than `page2`.
 */
static int memcmp_pages(struct page *page1, struct page *page2)
{
    char *addr1, *addr2;
    int ret;

    addr1 = kmap_atomic(page1);
    addr2 = kmap_atomic(page2);
    ret = memcmp(addr1, addr2, PAGE_SIZE);
    kunmap_atomic(addr2);
    kunmap_atomic(addr1);
    return ret;
}


/**
 * Determines whether two pages are identical.
 *
 * @param page1 The first page to compare.
 * @param page2 The second page to compare.
 * @return 1 if the pages are identical, 0 otherwise.
 */

static int pages_identical(struct page *page1, struct page *page2)
{
	return !memcmp_pages(page1, page2);
}


/**
 * Fill in the various fields related to pages in a process's memory. The field includes
 * the number of total pages, valid pages, invalid pages, shareable pages, and group.
 *
 * @param info Pointer to the process_memory_info structure.
 * @param mm Pointer to the mm_struct structure.
 */
static void count_pages(struct process_memory_info *info, struct mm_struct *mm)
{
    unsigned long nb_valid_pages = 0;
    unsigned long nb_shareable_pages = 0;
    unsigned long nb_group = 0;
    struct vm_area_struct *vma;
    unsigned long address;
    struct page *page;
    u32 hash;
    struct hash_count *entry;

    if (!mm)
    {
        return;
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

            // Traverse page tables to obtain the physical page associated with the virtual address
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
                nb_valid_pages++;

                if (vma->vm_flags & VM_READ) // readable pages
                {
                    // Get the page corresponding to the virtual address
                    page = pte_page(*ptep);

                    // Calculate the hash value for the page's content
                    hash = calc_checksum(page);

                    // Look up the hash value in the hash table
                    hash_for_each_possible(info->count_hashlist, entry, hlist_node, hash)
                    {
                        if (pages_identical(page, entry->page))
                        {
                            // Entry already exists, update it and counters
                            if (entry->count == 1)
                            {
                                nb_group++;
                                nb_shareable_pages++; //to take into account the 1st page
                            }
                            entry->count++;
                            nb_shareable_pages++;
                            goto next_page;
                        }
                    }

                    // Entry doesn't exist, add it to the hash table
                    entry = (struct hash_count *)kmalloc(sizeof(struct hash_count), GFP_KERNEL);
                    entry->hash = hash;
                    entry->count = 1;
                    entry->page = page;
                    hash_add(info->count_hashlist, &entry->hlist_node, hash);

                next_page:
                    continue;
                }
            }
        }
    }
    info->nb_total_pages += mm->total_vm;
    info->nb_valid_pages += nb_valid_pages;
    info->nb_invalid_pages += mm->total_vm - nb_valid_pages;
    info->nb_shareable_pages += nb_shareable_pages;
    info->nb_group += nb_group;
}


/**
 * Populates the process memory hashlist.
 *
 * This function is responsible for populating the hashlist that stores the process memory information.
 * It is a static function, meaning it can only be accessed within the same source file.
 *
 * @return The number of bytes populated in the hashlist, or a negative value if an error occurred.
 */
static ssize_t populate_process_memory_hashlist(void)
{
    ssize_t ret = 0;
    struct task_struct *task;
    struct process_memory_info *info;
    struct mm_struct *mm;
    struct pid_entry *new_pid_entry;

    // Iterate through each process
    for_each_process(task)
    {
        int i;
        // Get task's memory management struct (mm)
        mm = get_task_mm(task);
        if (!mm)
        {
            // Process(es) with no page must be ignored
            continue;
        }

        // Check if the entry already exists in the hash table
        hash_for_each_possible(process_memory_hashlist, info, hlist_node, hash_str(task->comm))
        {
            if (strncmp(info->name, task->comm, MAX_NAME_LENGTH) == 0)
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
                list_add_tail(&new_pid_entry->list_node, &info->pids);
                info->pid_count++;
                count_pages(info, mm);
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
        info->nb_total_pages = 0;
        info->nb_valid_pages = 0;
        info->nb_invalid_pages = 0;
        info->nb_shareable_pages = 0;
        info->nb_group = 0;
        // Initialize count hashlist
        for (i = 0; i < PAGE_SHIFT; i++) //what value to put
        {
            INIT_HLIST_HEAD(&info->count_hashlist[i]);
        }
        count_pages(info, mm);

        // Add the new entry to the hashtable
        hash_add(process_memory_hashlist, &info->hlist_node, hash_str(task->comm));

    next_process:
        continue;
    }

out_populate:
    return ret;
}


/**
 * Frees the memory allocated for a struct process_memory_info object.
 *
 * @param info A pointer to the struct process_memory_info object to be freed.
 */
static void free_process_memory_info(struct process_memory_info *info)
{
    struct pid_entry *pid_entry, *pid_tmp;
    struct hash_count *entry;
    struct hlist_node *tmp;
    unsigned int bkt;
    if (!info)
    {
        printk(KERN_ERR "Error: NULL pointer passed to free_process_memory_info");
        return;
    }

    // Free any allocated memory for the entry
    hash_del(&info->hlist_node);
    list_for_each_entry_safe(pid_entry, pid_tmp, &info->pids, list_node) {
        list_del(&pid_entry->list_node);
        kfree(pid_entry);
    }
    // Iterate through the hash table and free memory for each entry
    hash_for_each_safe(info->count_hashlist, bkt, tmp, entry, hlist_node)
    {
        hash_del(&entry->hlist_node);
        kfree(entry);
    }
    kfree(info);
}


/**
 * Frees the memory allocated for the process memory hashlist.
 *
 * This function is responsible for freeing the memory allocated for the process memory hashlist.
 * It should be called when the hashlist is no longer needed to prevent memory leaks.
 */
static void free_process_memory_hashlist(void)
{
    struct process_memory_info *info;
    struct hlist_node *tmp;
    unsigned int bkt;

    // Iterate through the hash table and free memory for each entry
    hash_for_each_safe(process_memory_hashlist, bkt, tmp, info, hlist_node)
    {
        free_process_memory_info(info);
    }
}


/**
 * Calculates the buffer size based on the given process memory information.
 *
 * @param info A pointer to the struct process_memory_info containing the process memory information.
 * @return The size of the buffer calculated based on the process memory information.
 */

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


/**
 * Generates a process information message based on the provided process memory information.
 *
 * @param info The process memory information.
 * @param output_buffer The buffer to store the generated message.
 * @param buffer_size The size of the output buffer.
 * @return The size of the generated message.
 */
static size_t generate_process_info_message(struct process_memory_info *info, char *output_buffer, size_t buffer_size)
{
    struct pid_entry *pid_entry;
    size_t tmp_buffer_size = 0;
    size_t tmp_size = 0;
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


/**
 * Formats the process memory information.
 *
 * @param info A pointer to the process_memory_info structure containing the memory information.
 * @return A pointer to the formatted memory information string.
 */
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


/**
 * @brief Formats the process memory information for all processes.
 *
 * This function takes no arguments and returns a pointer to a character array.
 * It formats the process memory information for all processes and returns the result as a string.
 *
 * @return A pointer to a character array containing the formatted process memory information.
 */
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


/**
 * Writes a message to a file.
 *
 * This function is responsible for writing the contents corresponding to the command entered in
 * the buffer `buff` to the file associated with the file structure `file`. The number of bytes 
 * to in the biffer is specified by `cnt`. The current file position is stored in `f_pos`.
 *
 * @param file  Pointer to the file structure representing the file to write to.
 * @param buff  Pointer to the buffer containing the message to write.
 * @param cnt   Number of bytes to write.
 * @param f_pos Pointer to the current file position.
 * @return      The number of bytes written, or a negative error code on failure.
 */
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
        struct process_memory_info *info;
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
            ret = -ESRCH;
            goto out_free_tmp_write_msg;
        }
        hash_for_each_possible(process_memory_hashlist, info, hlist_node, hash_str(name))
        {
            if (strncmp(info->name, name, MAX_NAME_LENGTH) == 0)
            {
                message = format_process_memory_info(info);
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
            ret = -ESRCH;
            goto out_free_tmp_write_msg;
        }
    }
    else if (strncmp(tmp, "DEL|", 4) == 0)
    {
        struct process_memory_info *info;
        char *name = tmp + 4;
        char *newline_ptr = strchr(name, '\n');
        if (newline_ptr) {
            *newline_ptr = '\0'; // Remove newline character
        }
        if (strlen(name) > MAX_NAME_LENGTH)
        {
            message = kstrdup("[ERROR]: No such process", GFP_KERNEL);
            printk(KERN_ERR "[ERROR]: No such process");
            ret = -ESRCH;
            goto out_free_tmp_write_msg;
        }
        hash_for_each_possible(process_memory_hashlist, info, hlist_node, hash_str(name))
        {
            if (strncmp(info->name, name, MAX_NAME_LENGTH) == 0)
            {
                free_process_memory_info(info);
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


/**
 * Show the proc information.
 *
 * This function is responsible for displaying the proc information in the given seq_file.
 *
 * @param a     The seq_file pointer to write the information to.
 * @param v     The pointer to the data structure associated with the proc information.
 *
 * @return      Returns an integer value indicating the status of the operation.
 */
static int show_the_proc(struct seq_file *a, void *v)
{
    seq_printf(a, "%s\n", message);
    return 0;
}


/**
 * Opens the proc file.
 *
 * This function is called when a process attempts to open the proc file.
 * It is responsible for initializing the file structure and performing any necessary setup.
 *
 * @param inode Pointer to the inode structure representing the proc file.
 * @param file Pointer to the file structure representing the opened file.
 * @return 0 on success, or a negative error code on failure.
 */
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


/**
 * @brief Initializes the module.
 *
 * This function is called when the module is loaded into the kernel.
 * It performs the necessary initialization tasks for the module.
 *
 * @return Returns 0 on success, or a negative error code on failure.
 */
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


/**
 * @brief Stops the module.
 *
 * This function is called when the module is removed from the kernel.
 * It performs the necessary cleanup tasks for the module.
 */
static void __exit module_stop(void)
{
    if (message)
    {
        kfree(message); //free memory
    }
    // free memory
    free_process_memory_hashlist();
    // remove proc entry
    remove_proc_entry(DEV_NAME, NULL);
}

module_init(module_start);  //module initialization
module_exit(module_stop);   //module exit
