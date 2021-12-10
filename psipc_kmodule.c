#include <linux/cdev.h> 
#include <linux/delay.h> 
#include <linux/device.h> 
#include <linux/fs.h> 
#include <linux/init.h> 
#include <linux/irq.h> 
#include <linux/kernel.h> 
#include <linux/module.h> 
#include <linux/poll.h> 
#include <linux/string.h>
#include <linux/list.h>
#include <linux/signal.h>
#include <linux/types.h>
#include <linux/namei.h>
#include <linux/cred.h>
#include <linux/spinlock.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ottavia Belotti and Riccardo Izzo");
MODULE_DESCRIPTION("Publisher/subscriber IPC");
MODULE_VERSION("1.0");

/* new_topic functions */
static int new_topic_open(struct inode *, struct file *); 
static int new_topic_release(struct inode *, struct file *); 
static ssize_t new_topic_write(struct file *, const char __user *, size_t, loff_t *); 

/* subscribe functions */
static ssize_t subscribe_write(struct file*, const char __user *, size_t, loff_t*);

/* subscribers_list functions */
static ssize_t subs_list_read(struct file*, char __user *, size_t, loff_t*);

/* signal_nr functions */
static ssize_t signal_nr_write(struct file*, const char __user *, size_t, loff_t*);

/* endpoint functions */
static ssize_t endpoint_write(struct file*, const char __user *, size_t, loff_t*);
static ssize_t endpoint_read(struct file*, char __user *, size_t, loff_t*);

/* other functions */
static int topic_files_open(struct inode *, struct file *);
static int topic_files_release(struct inode *, struct file *);
static void release_files(void); 
static struct pid_node* search_pid_node(struct list_head*);
static struct topic_node* search_node(char*);  
static int pid_atoi(char*);
static int signal_atoi(char*);
static int set_files_ownership(const char *msg);
static int set_topic_ownership(const char *msg);
 
#define SUCCESS 0 
#define NEW_TOPIC_PATH "psipc/new_topic" /* new_topic device file path */ 
#define TOPICS_PATH "psipc/topics/"      /* topic folder path */
#define FULL_PATH "/dev/psipc/topics/"   /* topic folder full path */
#define BUF_LEN 300                      /* max length of the message from the device */ 
#define NUM_SPECIAL_FILES 4              /* number of device files for every topic */
#define MAX_SIZE_PID 10                  /* on a 64-bit system the the max pid value is 4194304 */
 
static struct file_operations new_topic_dev_fops = { 
    .owner      = THIS_MODULE,
    .write      = new_topic_write, 
    .open       = new_topic_open, 
    .release    = new_topic_release, 
};

static struct file_operations subscribe_fops = {
    .owner      = THIS_MODULE,
    .write      = subscribe_write,
    .open       = topic_files_open,
    .release    = topic_files_release,
};

static struct file_operations subscribers_list_fops = {
    .owner      = THIS_MODULE,
    .read       = subs_list_read,
    .open       = topic_files_open,
    .release    = topic_files_release,
}; 

static struct file_operations signal_nr_fops = {
    .owner      = THIS_MODULE,
    .write      = signal_nr_write,
    .open       = topic_files_open,
    .release    = topic_files_release,
};

static struct file_operations endpoint_fops = {
    .owner      = THIS_MODULE,
    .read       = endpoint_read,
    .write      = endpoint_write,
    .open       = topic_files_open,
    .release    = topic_files_release,
};

/* multi-processes safety */
enum { 
    CDEV_NOT_USED = 0, 
    CDEV_EXCLUSIVE_OPEN = 1, 
};

/* boolean */
enum{
    FALSE =  0,
    TRUE = 1,
};
 
static atomic_t new_topic_already_open = ATOMIC_INIT(CDEV_NOT_USED); /* to not have more publisher request for a new topic concurrently */
static DEFINE_RWLOCK(topic_list_rwlock);                             /* to sync operations on topic_list_head list */

/* topic_node struct represents a topic directory in /dev/psipc/topics */
static struct topic_node{
    char *dir_name;                                 /* path name of the topic */
    struct class file_dev_cls[NUM_SPECIAL_FILES];   /* array of struct class, one for every device file */
    dev_t devices[NUM_SPECIAL_FILES];               /* array of dev_t, one for every device file, used to store device numbers */
    struct list_head pid_list_head;                 /* head of list of struct pid_node */
    int signal_nr;                                  /* type of signal to send to all the topic subscribers */
    struct list_head list;
    int n_read;                                     /* number of read operations executed on endpoint by the subscribers */
    int n_subscriber;                               /* total number of subscribers that will/are currently reading the message */
    int n_new_subscriber;                           /* number of subscribers that arrive while a signal has already been sent and other
                                                     * subscribers are potentially reading the message. The new subscribers won't read it.*/
    char *message;                                  /* message written to endpoint */
    atomic_t is_reading;                            /* true if a signal has been sent. It goes back to false when publisher wants
                                                     * to write again a message. */
    atomic_t subs_read_flag;

    /* Concurrency */
    rwlock_t subscribe_rwlock;          /* read-write lock for interaction between read operations on subscribers_list file 
                                         * and write operations on subscribe file. */
    rwlock_t signal_nr_rwlock;          /* at most one publisher is allowed to write on the signal_nr device file.
                                         * Endpoint cannot be written if the publisher is writing the signal on signal_nr
                                         * file and viceversa. */
    rwlock_t endpoint_rwlock;           /* read-write lock for interaction between read operations and write operations on endpoint file. */
};

/* pid_node struct is a node in the list of subscribers' pids to a specific topic_node */
static struct pid_node{
    int pid;                    /* pid of the subscriber */
    atomic_t has_been_notified; /* indicates if the subscriber has already been notified with the signal */
    atomic_t has_read;          /* indicates if the subscriber has already read the message*/
    struct list_head list;
};

static struct list_head topic_list_head; /* head of list of struct topic_node */

static int major;         /* major number of the device file */
static char msg[BUF_LEN+1]; /* the msg the device will give when asked */ 
 
static struct class *new_topic_cls; 

const char* files[] = {"/subscribe", "/subscribers_list", "/signal_nr", "/endpoint"}; /* device files name */

const struct file_operations* fops[] = {&subscribe_fops, &subscribers_list_fops, &signal_nr_fops, &endpoint_fops}; /* device files file_operations */

/*
* It sets read and write permission to the device file. This function has to be assigned to a class->devnode field.
*/
static char *cls_set_readAndWrite_permission(struct device *dev, umode_t *mode){
    if(mode!=NULL){
        *mode = (umode_t)0660;
    }
    return NULL;
}

/*
* It sets global write-only permission to the device file. This function has to be assigned to a class->devnode field.
*/
static char *cls_set_writeOnly_permission_global(struct device *dev, umode_t *mode){
    if(mode!=NULL){
        *mode = (umode_t)0222;
    }
    return NULL;
}

/*
* It sets write-only permission to the device file. This function has to be assigned to a class->devnode field.
*/
static char *cls_set_writeOnly_permission(struct device *dev, umode_t *mode){
    if(mode!=NULL){
        *mode = (umode_t)0220;
    }
    return NULL;
}

/*
* It sets read-only permission to the device file. This function has to be assigned to a class->devnode field.
*/
static char *cls_set_readOnly_permission(struct device *dev, umode_t *mode){
    if(mode!=NULL){
        *mode = (umode_t)0440;
    }
    return NULL;
}

/*
* Called when the module is loaded with insmod.
* It creates the /dev/psipc directory and the new_topic character device in it.
*/
static int __init psipc_init(void)
{ 
    /* initialize the list of topics */
    INIT_LIST_HEAD(&topic_list_head);
    major = register_chrdev(0, NEW_TOPIC_PATH, &new_topic_dev_fops); 
 
    if (major < 0) { 
        pr_alert("register_chrdev: ERROR: registering char device failed with %d\n", major); 
        return major; 
    } 
 
    pr_info("Assigned major number: %d\n", major); 
 
    new_topic_cls = class_create(THIS_MODULE, NEW_TOPIC_PATH);
    if(IS_ERR(new_topic_cls)){

    }
    new_topic_cls->devnode = cls_set_writeOnly_permission_global; 
    device_create(new_topic_cls, NULL, MKDEV(major, 0), NULL, NEW_TOPIC_PATH); 
 
    pr_info("Device created on /dev/%s\n", NEW_TOPIC_PATH); 
 
    return SUCCESS; 
} 
 
/*
* Called when the module is unloaded with rmmmod.
* It deletes all the device files for every topic and finally delete the /dev/psipc directory.
*/
static void __exit psipc_exit(void) 
{ 
    release_files();
    device_destroy(new_topic_cls, MKDEV(major, 0)); 
    class_destroy(new_topic_cls); 
    unregister_chrdev(major, NEW_TOPIC_PATH); 
    pr_info("Device /dev/%s has been unregistered.\n", NEW_TOPIC_PATH);
} 
 
/*
* Called whenever a process attempts to open the new_topic device file.
*/
static int new_topic_open(struct inode *inode, struct file *file) 
{ 
    /*
    * Read the 32-bit value of new_topic_already_open through its address.
    * Compute (new_topic_already_open == CDEV_NOT_USED) ?  CDEV_EXCLUSIVE_OPEN : old and store result in new_topic_already_open. 
    * The function returns old version of new_topic_already_open.
    */
    if (atomic_cmpxchg(&new_topic_already_open, CDEV_NOT_USED, CDEV_EXCLUSIVE_OPEN)) 
        return -EBUSY; 

    try_module_get(THIS_MODULE); 
 
    return SUCCESS; 
} 
 
/* 
* Called when a process closes the new_topic device file.
*/
static int new_topic_release(struct inode *inode, struct file *file) 
{  
    atomic_set(&new_topic_already_open, CDEV_NOT_USED); 
 
    module_put(THIS_MODULE); 
 
    return SUCCESS; 
}

/* 
* Called when a process writes to the new_topic device file.
*/
static ssize_t new_topic_write(struct file *filp, const char __user *buff, size_t len, loff_t *off) 
{ 
    int i, created_sub, path_len=0, bytes_written; 
    char *dir, *path;
    struct topic_node *elem;
    struct class *cls;
 
    for (i = 0; i < len && i < BUF_LEN; i++) 
        get_user(msg[i], buff + i);

    bytes_written = i;
    msg[i-1] = '\0';

    path_len += strlen(TOPICS_PATH);
    path_len += strlen(msg);

    if(!(dir = (char*)kmalloc(path_len, GFP_KERNEL))){
        pr_alert("kmalloc: ERROR: cannot allocate memory for %s\n", msg);
        return -ENOMEM;
    }

    strcpy(dir, TOPICS_PATH);
    strcat(dir, msg);

    struct topic_node *ptr;
    read_lock(&topic_list_rwlock);

    /* Check if already exists a topic with the same name */
    if(!(list_empty(&topic_list_head))){
        list_for_each_entry(ptr, &topic_list_head, list){
            if(strcmp(ptr->dir_name, dir) == 0){
                pr_info("Already exists a topic with the name: %s\n", msg);
                read_unlock(&topic_list_rwlock);
                return EINVAL;
            }
        }
    }
    read_unlock(&topic_list_rwlock);

    if(!(elem = (struct topic_node*)kmalloc(sizeof(*elem), GFP_KERNEL))){
        pr_alert("kmalloc: ERROR: cannot allocate memory for the topic_node\n");
        return -ENOMEM;
    }

    elem->dir_name = dir;
    elem->signal_nr = -1;
    elem->n_read = 0;
    elem->n_subscriber = 0;
    elem->n_new_subscriber = 0;
    atomic_set(&(elem->is_reading), FALSE);
    atomic_set(&(elem->subs_read_flag), FALSE);
    rwlock_init(&(elem->signal_nr_rwlock));
    rwlock_init(&(elem->subscribe_rwlock));
    rwlock_init(&(elem->endpoint_rwlock));
    
    /* Create four device files in a topic */
    for(i = 0; i < NUM_SPECIAL_FILES; i++){
        if(!(path = (char*)kmalloc(path_len + strlen(files[i]), GFP_KERNEL))){
            pr_alert("kmalloc: ERROR: cannot allocate memory for path\n");
            return -ENOMEM;
        }

        strcpy(path, dir);
        strcat(path, files[i]);

        created_sub = register_chrdev(0, path, fops[i]);
        if(created_sub<0){
            pr_alert("register_chrdev: ERROR: cannot create directory /dev/%s\n", path);
        }

        cls = class_create(THIS_MODULE, path);
        if(IS_ERR(cls)){
            pr_alert("class_create: ERROR: cannot create class for /dev/%s\n", path);
        }

        if(i==0 || i==2){ /* subscribe + signal_nr device files */
            cls->devnode = cls_set_writeOnly_permission;
        }else if(i==1){ /* subscribers_list device files */
            cls->devnode = cls_set_readOnly_permission;
        }else{ /* endpoint device files */
            cls->devnode = cls_set_readAndWrite_permission; 
        }
        elem->devices[i] = MKDEV(created_sub, 0);
        device_create(cls, NULL, elem->devices[i], NULL, path); 
        elem->file_dev_cls[i] = *cls;

        kfree(path);
    }

    set_files_ownership(msg);
    set_topic_ownership(msg);

    /* initialize list of pids */
    INIT_LIST_HEAD(&(elem->pid_list_head));

    write_lock(&topic_list_rwlock);
    list_add(&(elem->list), &topic_list_head);
    write_unlock(&topic_list_rwlock);

    pr_info("Topic %s succesfully created.\n", elem->dir_name);
    
    return bytes_written; 
}

/*
* Called whenever a process attempts to open one device file among: subscribe, subscribers_list, signal_nr and endpoint.
*/
static int topic_files_open(struct inode *inode, struct file *file){
    try_module_get(THIS_MODULE);

    return SUCCESS;
}

/* 
* Called when a process closes one device file among: subscribe, subscribers_list, signal_nr and endpoint.
*/
static int topic_files_release(struct inode *inode, struct file *file){
    module_put(THIS_MODULE);

    return SUCCESS;
}  

/* 
* Called when a process writes to the subscribe device file.
*/
static ssize_t subscribe_write(struct file *filp, const char __user *buff, size_t len, loff_t *off){
    int i, bytes_written;
    char *dentry;
    struct topic_node *node;
    struct pid_node* pid_node;
 
    for (i = 0; i < len && i < BUF_LEN; i++) 
        get_user(msg[i], buff + i);

    bytes_written = i;
    msg[i-1] = '\0';

    if(!(pid_node = (struct pid_node*)kmalloc(sizeof(struct pid_node), GFP_KERNEL))){
        pr_alert("kmalloc: ERROR: cannot allocate memory for the pid_node\n");
        return -ENOMEM;
    }
    pid_node->pid = pid_atoi(msg);
    atomic_set(&(pid_node->has_been_notified), FALSE);
    atomic_set(&(pid_node->has_read), FALSE);
    if(pid_node->pid <0){
        pr_alert("ERROR: %s is not a pid\n", msg);
        return bytes_written;
    }

    dentry = filp->f_path.dentry->d_parent->d_iname;
    node = search_node(dentry);
    if(node==NULL){
        pr_alert("search_node: ERROR: cannot find the node\n");
        return bytes_written;
    }

    write_lock(&(node->subscribe_rwlock));
    
    if(atomic_read(&(node->is_reading))){
        node->n_new_subscriber++;
    }else{
        node->n_subscriber++;
    }

    list_add(&(pid_node->list), &(node->pid_list_head));
    pr_info("Process with pid %d has successfully subscribed to the topic %s\n", pid_node->pid, node->dir_name);

    write_unlock(&(node->subscribe_rwlock));
    
    return bytes_written;
}


/*
* Called when a process, which already opened the subscribers_list device file, attempts to read from it.
* It prints the list of pid of subscribed processes.
*/
static ssize_t subs_list_read(struct file *filp, char __user *buffer, size_t length, loff_t *offset){
    int bytes_read = 0; 
    struct pid_node *ptr;
    struct topic_node *node;
    char *dentry;

    dentry = filp->f_path.dentry->d_parent->d_iname;
    node = search_node(dentry);

    if(node==NULL){
        pr_alert("Node not found.\n");
        return -EINVAL;
    }

    if (atomic_read(&(node->subs_read_flag)) == TRUE) { /* we are at the end of message */
        atomic_set(&(node->subs_read_flag), FALSE);
        *offset = 0; /* reset the offset */
        return 0; /* signify end of file */
    } 

    read_lock(&(node->subscribe_rwlock));

    list_for_each_entry(ptr, &(node->pid_list_head), list){
        int len, i = 0;
        char *str;
        str = (char*)kmalloc(MAX_SIZE_PID, GFP_KERNEL);
        snprintf(str, MAX_SIZE_PID, "%d", ptr->pid);
    
        len = strlen(str);

        /* Actually put the data into the buffer */ 
        while (len > 0) { 
            put_user(str[i++], buffer++);
            len--; 
            bytes_read++;
        } 
        put_user(' ', buffer++);
        bytes_read++;
        kfree(str);
    }

    read_unlock(&(node->subscribe_rwlock));

    put_user('\n', buffer++);
    bytes_read++;

    atomic_set(&(node->subs_read_flag), TRUE);

    *offset += bytes_read; 
    
    return bytes_read;
}

/* 
* Called when a process writes to the signal_nr device file.
* Each time the publisher rewrites on signal_nr file, the signal is overwritten.
*/
static ssize_t signal_nr_write(struct file *filp, const char __user *buff, size_t len, loff_t *off){
    int i, written_bytes = 0, signal_nr;
    char* dentry;
    struct topic_node *node;

    for (i = 0; i < len && i < BUF_LEN; i++) 
        get_user(msg[i], buff + i);

    written_bytes = i;
    msg[i-1] = '\0';

    dentry = filp->f_path.dentry->d_parent->d_iname;
    pr_info("Dentry to search: %s\n", dentry);
    node = search_node(dentry);
    if(node==NULL){
        pr_alert("ERROR: node not found\n");
        return EFAULT;
    }

    write_lock(&(node->signal_nr_rwlock));

    signal_nr = signal_atoi(msg);
    if(signal_nr==EINVAL){
        write_unlock(&(node->signal_nr_rwlock));
        pr_alert("ERROR: signal_nr_write: signal is not a number\n");
        return EINVAL;
    }   
    if(signal_nr < 0){
        write_unlock(&(node->signal_nr_rwlock));
        pr_alert("ERROR: signal_nr_wirte: negative signal is invalid.\n");
        return EINVAL;
    }
    node->signal_nr = signal_nr;

    write_unlock(&(node->signal_nr_rwlock));

    pr_info("Written signal: %d\n", node->signal_nr);

    return written_bytes;
}

/* 
* Called when a process writes to the endpoint device file.
*/
static ssize_t endpoint_write(struct file *filp, const char __user *buff, size_t len, loff_t *off){
    int i, written_bytes;
    struct topic_node *node;
    struct list_head *ptr, *temp_pid_node;
    struct pid_node *pid_entry;
    char* dentry;
    struct kernel_siginfo info;
    struct pid* pid;

    dentry = filp->f_path.dentry->d_parent->d_iname;
    pr_info("Dentry to search: %s\n", dentry);
    node = search_node(dentry);
    if(node==NULL){
        pr_alert("Node not found\n");
        return EFAULT;
    }

    /* delete from the list all the subscribers that are no longer alive */
    write_lock(&(node->subscribe_rwlock));
    if(list_empty(&(node->pid_list_head))){
        node->n_subscriber = 0;
        node->n_new_subscriber = 0;
    }else{
        list_for_each_safe(ptr, temp_pid_node, &(node->pid_list_head)){
            pid_entry = list_entry(ptr, struct pid_node, list);
            pid = find_vpid(pid_entry->pid);
            /* it sends the null signal just to understand if the subscriber is still alive */
            if(kill_pid(pid, 0, &info) < 0) {
                if(atomic_read(&(pid_entry->has_been_notified))){ 
                    node->n_subscriber--;
                    if(atomic_read(&(pid_entry->has_read))){
                        node->n_read--;
                    }
                }
                else node->n_new_subscriber--;
                list_del(ptr);
                pr_alert("ERROR: subscriber %d is no longer alive and will be eliminated from the list\n", pid_entry->pid);
            }
        }
    }
    write_unlock(&(node->subscribe_rwlock));

    if(node->n_subscriber == 0 && node->n_new_subscriber == 0){
        pr_info("All old subscribers are no longer alive.\n");
    }

    read_lock(&(node->signal_nr_rwlock));
    write_lock(&(node->endpoint_rwlock));
    if(node->message!=NULL && node->n_read < node->n_subscriber){
        /* not all the subscribers have finished to read the previous message, so do not write again yet */
        write_unlock(&(node->endpoint_rwlock));
        read_unlock(&(node->signal_nr_rwlock));
        pr_alert("ERROR: read %d, subs %d\n", node->n_read, node->n_subscriber);
        return -EBUSY;
    }
    
    atomic_set(&(node->is_reading), FALSE);

    for (i = 0; i < len && i < BUF_LEN; i++) 
        get_user(msg[i], buff + i);

    written_bytes = i;
    msg[i-1] = '\0';
    pr_info("Written: %s\n", msg);

    /* overwrites the previous message */
    if(node->message != NULL){
        kfree(node->message);
    }

    if(!(node->message = (char*)kmalloc(sizeof(written_bytes + 1), GFP_KERNEL))){
        write_unlock(&(node->endpoint_rwlock));
        read_unlock(&(node->signal_nr_rwlock));
        pr_alert("kmalloc: ERROR: cannot allocate memory for node->message\n");
        return -ENOMEM;
    }
    strcpy(node->message, msg);

    /* in case the publisher hasn't specified the signal to send */
    if((node->signal_nr) == -1){
        kfree(node->message);
        node->message = NULL;
        write_unlock(&(node->endpoint_rwlock));
        read_unlock(&(node->signal_nr_rwlock));
        pr_info("Publisher hasn't specified the signal to send to subscribers. No signal will be sent and message is discarded.\n");
        return written_bytes;
    }
    
    /* in case there are no subscribers */
    if(list_empty(&(node->pid_list_head))){
        kfree(node->message);
        node->message = NULL;
        write_unlock(&(node->endpoint_rwlock));
        read_unlock(&(node->signal_nr_rwlock));
        pr_info("No subscribers to notify. Message is discarded.\n");
        return written_bytes;
    }

    info.si_signo = node->signal_nr;
    info.si_int = 1;

    node->n_read = 0;
    node->n_subscriber += node->n_new_subscriber;
    node->n_new_subscriber = 0;

    write_lock(&(node->subscribe_rwlock));

    /* send the signal to every subscriber */
    list_for_each_safe(ptr, temp_pid_node, &(node->pid_list_head)){
        pid_entry = list_entry(ptr, struct pid_node, list);
        pid = find_vpid(pid_entry->pid);
        atomic_set(&(pid_entry->has_been_notified), FALSE);
        atomic_set(&(pid_entry->has_read), FALSE);
        /* if a subscriber is no longer alive the kill_pid() function returns a negative value, the number of subscribers is decreased and the corresponding pid_node is deleted */
        if(kill_pid(pid, node->signal_nr, &info) < 0) {
            list_del(ptr);
            node->n_subscriber--;
            pr_alert("ERROR: unable to send signal\n");
        }
        else atomic_set(&(pid_entry->has_been_notified), TRUE);
    }
    atomic_set(&(node->is_reading), TRUE);
    
    write_unlock(&(node->subscribe_rwlock));
    write_unlock(&(node->endpoint_rwlock));
    read_unlock(&(node->signal_nr_rwlock));

    /*Truncation of message*/
    if(len > BUF_LEN){
        pr_alert("Message has been truncated because it is too long. Max %d characters per message.\n", BUF_LEN);
        written_bytes= len;
    }

    return written_bytes;
}

/*
* Called when a process, which already opened the endpoint device file, attempts to read from it.
* It prints the message written to endpoint
*/
static ssize_t endpoint_read(struct file *filp, char __user *buffer, size_t length, loff_t *offset){
    int bytes_read = 0, i = 0, len; 
    struct topic_node *node;
    struct pid_node *pidNode;
    char *dentry, *msg_ptr;

    dentry = filp->f_path.dentry->d_parent->d_iname;
    node = search_node(dentry);
    if(node==NULL){
        pr_alert("ERROR: node not found\n");
        return -EFAULT;
    }

    pidNode = search_pid_node(&(node->pid_list_head));
    if(pidNode==NULL){
        pr_alert("ERROR: pid_node not found\n");
        return EFAULT;
    }

    if(atomic_read(&(pidNode->has_read)) == TRUE) { /* we are at the end of message */
        *offset = 0; /* reset the offset */
        return 0; /* signify end of file */
    }

    read_lock(&(node->endpoint_rwlock));
    msg_ptr = node->message; 
    len = strlen(msg_ptr);

    if((node->n_read == node->n_subscriber) || (len == 0)){
        put_user('\0', buffer++);
        bytes_read++;
    }
    else{
        /* Actually put the data into the buffer */ 
        while (len > 0) { 
            put_user(msg_ptr[i++], buffer++);
            len--; 
            bytes_read++;
        } 
    }

    /* it's the first time for this pid reading this current message*/
    if(atomic_read(&(pidNode->has_read)) == FALSE){
        atomic_set(&(pidNode->has_read), TRUE);
        node->n_read++;
    }
    
    read_unlock(&(node->endpoint_rwlock));

    *offset += bytes_read; 

    return bytes_read;
}

/*
* It releases all the device files for every topic.
*/
static void release_files(void){
    int n_files;
    struct list_head *ptr1, *ptr2, *temp1, *temp2;
    struct topic_node *entry, *entry_temp;

    write_lock(&topic_list_rwlock);
    if(!list_empty(&topic_list_head)){
        entry = list_first_entry_or_null(&topic_list_head, struct topic_node, list);

        if(entry == NULL){
            pr_info("No topic to delete.\n");
            write_unlock(&topic_list_rwlock);
            return;
        }

        list_for_each_safe(ptr1, temp1, &topic_list_head){
            entry_temp = list_entry(ptr1, struct topic_node, list);
            if(entry_temp!=NULL){
                if(!list_empty(&(entry_temp->pid_list_head))){
                    /* delete the list of pids */
                    list_for_each_safe(ptr2, temp2, &(entry_temp->pid_list_head)){
                        list_del(ptr2);
                    }
                }else{
                    pr_info("No pid list to free\n");
                }
                pr_info("All pid freed\n");

                /* delete the four device files */
                for(n_files=0; n_files < NUM_SPECIAL_FILES; n_files++){
                    char *str = (char*)kmalloc(strlen(entry_temp->dir_name) + strlen(files[n_files]), GFP_KERNEL);
                    strcpy(str, entry_temp->dir_name);
                    strcat(str, files[n_files]);
                    device_destroy(&(entry_temp->file_dev_cls[n_files]), entry_temp->devices[n_files]);
                    class_destroy(&(entry_temp->file_dev_cls[n_files]));
                    pr_info("Delete device file: %s/%s\n", str, files[n_files]);
                    unregister_chrdev(major, str);
                    kfree(str);
                }
                
                /* delete the message written in endpoint */
                if(entry_temp->message != NULL){
                    kfree(entry_temp->message);
                    pr_info("Endpoint message freed");
                }

                if(entry_temp->dir_name!=NULL){
                    kfree(entry_temp->dir_name);
                }

                if(ptr1!=NULL){
                    list_del(ptr1);
                }else
                    pr_alert("ERROR: no pointer to free\n");
            }else
                pr_alert("ERROR: null entry\n");
        }

        write_unlock(&topic_list_rwlock);
    }
}

/*
* It searches in the list the correct topic_node given the topic path.
*/
static struct topic_node* search_node(char *dir){
    char *path;
    struct topic_node *ptr;

    if(!(path = (char*)kmalloc(strlen(TOPICS_PATH) + strlen(dir), GFP_KERNEL))){
        pr_alert("kmalloc: ERROR: cannot allocate memory for the path\n");
        return NULL;
    }

    strcpy(path, TOPICS_PATH);
    strcat(path, dir);

    read_lock(&topic_list_rwlock);
    list_for_each_entry(ptr, &topic_list_head, list){
        if(strcmp(ptr->dir_name, path)==0){
            read_unlock(&topic_list_rwlock);
            return ptr;
        }
    }
    read_unlock(&topic_list_rwlock);

    return NULL;
}

/*
* It searches in the list the correct pid_node.
*/
static struct pid_node* search_pid_node(struct list_head *head){
    struct pid_node *ptr;

    list_for_each_entry(ptr, head, list){
        if(ptr->pid == current->pid){
            return ptr;
        }
    }
    return NULL;
}

/*
* Convert string of numbers into an integer pid (non-negative). Return EINVAL if the given string is not a pid.
*/
static int pid_atoi(char *s){
    int n=0, i;

    for(i=0; s[i]!='\0'; i++){
        if(s[i]<'0'  || s[i]>'9'){
            pr_alert("ERROR: %s is not a number\n", s);
            return -1;
        }
        n = n*10 + (s[i] - '0');
    }
    return n;
}

/*
* Convert string of numbers into an integer. Return EINVAL if the given string does not represent an integer.
*/
static int signal_atoi(char *s){
    int n=0, i;
    char negative_flag = '0'; /* 0: positive number, 1: negative number */

    for(i=0; s[i]!='\0'; i++){
        if((s[i]!='-' && (s[i]<'0' || s[i]>'9')) || (s[i]=='-' && i!=0)){
            pr_alert("ERROR: %s is not a number\n", s);
            return EINVAL;
        }
        if(s[i]=='-')
            negative_flag = '1';
        else{
            n = n*10 + (s[i] - '0');
        }
    }

    if(negative_flag=='1')
        n = -n;
    
    return n;
}

/*
* It sets the user as the owner of the device files in the topic.
*/
static int set_files_ownership(const char *msg){
    int i;
    char *full_path, *temp;
    struct path path_struct;
    struct inode *inode;
    kuid_t uid = current_uid();
    kgid_t gid = current_gid();

    if(!(temp = (char*)kmalloc(strlen(FULL_PATH) + strlen(msg), GFP_KERNEL))){
            pr_alert("kmalloc: ERROR: cannot allocate memory for temp\n");
            return -ENOMEM;
    }
    strcpy(temp, FULL_PATH);
    strcat(temp, msg);

    for(i = 0; i < NUM_SPECIAL_FILES; i++){
        if(!(full_path = (char*)kmalloc(strlen(temp) + strlen(files[i]), GFP_KERNEL))){
            pr_alert("kmalloc: ERROR: cannot allocate memory for full_path\n");
            return -ENOMEM;
        }
        strcpy(full_path, temp);
        strcat(full_path, files[i]);
        kern_path(full_path, LOOKUP_FOLLOW, &path_struct);
        inode = path_struct.dentry->d_inode;
        inode->i_uid = uid;
        inode->i_gid = gid;
        kfree(full_path);
    }
    kfree(temp);
    return 0;
}

/*
* It sets the user as the owner of the topic.
*/
static int set_topic_ownership(const char *msg){
    char *full_path;
    struct path path_struct;
    struct inode *inode;
    kuid_t uid = current_uid();
    kgid_t gid = current_gid();

    if(!(full_path = (char*)kmalloc(strlen(FULL_PATH) + strlen(msg), GFP_KERNEL))){
            pr_alert("kmalloc: ERROR: cannot allocate memory for full_path\n");
            return -ENOMEM;
    }
    strcpy(full_path, FULL_PATH);
    strcat(full_path, msg);
    kern_path(full_path, LOOKUP_FOLLOW, &path_struct);
    inode = path_struct.dentry->d_inode;
    inode->i_uid = uid;
    inode->i_gid = gid;
    kfree(full_path);
    return 0;
}
 
module_init(psipc_init); 
module_exit(psipc_exit); 
