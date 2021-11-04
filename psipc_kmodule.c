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

static int new_topic_open(struct inode *, struct file *); 
static int new_topic_release(struct inode *, struct file *); 
static ssize_t new_topic_read(struct file *, char __user *, size_t, loff_t *); 
static ssize_t new_topic_write(struct file *, const char __user *, size_t, loff_t *); 
static ssize_t subs_list_read(struct file*, char __user *, size_t, loff_t*);//might not be needed
static ssize_t subscribe_write(struct file*, const char __user *, size_t, loff_t*);
static ssize_t signal_nr_write(struct file*, const char __user *, size_t, loff_t*);
static ssize_t endpoint_write(struct file*, const char __user *, size_t, loff_t*);

static int subscribe_open(struct inode*, struct file*);
static int signal_nr_open(struct inode*, struct file*);
static int endpoint_open(struct inode*, struct file*);
static int subs_list_open(struct inode*, struct file*);   
static int subscribe_release(struct inode*, struct file*);                   
static int signal_nr_release(struct inode*, struct file*);
static int endpoint_release(struct inode*, struct file*);
static int subs_list_release(struct inode*, struct file*);

static void release_files(void); 
static void display_list(void);
static void display_pid_list(struct list_head*);
static struct exchange_node_s* search_node(char*);  
static int pro_atoi(char*);
 
#define SUCCESS 0 
#define ROOT_DIR "psipc"
#define NEW_TOPIC_REQ_NAME "psipc/new_topic" /* Dev name as it appears in /proc/devices   */ 
#define TOPICS_DIR "psipc/topics/"
#define BUF_LEN 100 /* Max length of the message from the device */ 
#define MAX_SUB_DIR 10
#define NUM_SPECIAL_FILES 4


 
static int major; /* it will be the same one because they're all of the same type*/
static int topics_counter = 0;

enum { 
    CDEV_NOT_USED = 0, 
    CDEV_EXCLUSIVE_OPEN = 1, 
}; 
 
/* Is device open? Used to prevent multiple access to device */ 
static atomic_t already_open = ATOMIC_INIT(CDEV_NOT_USED); 
static atomic_t subscribers_list_already_open = ATOMIC_INIT(CDEV_NOT_USED);
 
static char msg[BUF_LEN]; /* The msg the device will give when asked */ 
 
static struct class *new_topic_cls; 
 
static struct file_operations new_topic_dev_fops = { 
	.owner = THIS_MODULE,
    .read = new_topic_read, 
    .write = new_topic_write, 
    .open = new_topic_open, 
    .release = new_topic_release, 
};

static struct file_operations subscribe_fops = {
    .owner = THIS_MODULE,
    .write = subscribe_write,
    .open = subscribe_open,
    .release = subscribe_release,
};

static struct file_operations subscribers_list_fops = {
    .owner = THIS_MODULE,
    .read = subs_list_read,
    .open = subs_list_open,
    .release = subs_list_release,
}; 

static struct file_operations signal_nr_fops = {
    .owner = THIS_MODULE,
	.write = signal_nr_write,
	.open = signal_nr_open,
	.release = signal_nr_release,
};

static struct file_operations endpoint_fops = {
    .owner = THIS_MODULE,
	.write = endpoint_write,
	.open = endpoint_open,
	.release = endpoint_release,
};

static struct exchange_node_s{
	struct class file_dev_cls[NUM_SPECIAL_FILES];
    dev_t devices[NUM_SPECIAL_FILES];
	char *dir_name;
    //dentry *dentry;
    struct list_head subscribers_list_head; //list for pids, unsigned int
    int nr_signal;
    //endpoint file data? It should be a real file
    struct list_head list;
};

static struct subscribers_pid_s{
    int pid;
    struct list_head list;
};

static struct list_head topicsHead;

const char* files[] = {"/subscribe", "/subscribers_list", "/signal_nr", "/endpoint"};

const struct file_operations* fops[] = {&subscribe_fops, &subscribers_list_fops, &signal_nr_fops, &endpoint_fops};

//to set device permissions
static char *cls_devnode_setting(struct device *dev, umode_t *mode){
    if(mode!=NULL){
        *mode = (umode_t)0666;
    }
    return NULL;
}

static char *cls_set_writeOnly_permission(struct device *dev, umode_t *mode){
    if(mode!=NULL){
        *mode = (umode_t)0622;
    }
    return NULL;
}

static char *cls_set_readOnly_permission(struct device *dev, umode_t *mode){
    if(mode!=NULL){
        *mode = (umode_t)0644;
    }
    return NULL;
}


static int __init chardev_init(void)
{ 
    INIT_LIST_HEAD(&topicsHead);
    major = register_chrdev(0, NEW_TOPIC_REQ_NAME, &new_topic_dev_fops); 
 
    if (major < 0) { 
        pr_alert("Registering char device failed with %d\n", major); 
        return major; 
    } 
 
    pr_info("I was assigned major number %d.\n", major); 
 
    new_topic_cls = class_create(THIS_MODULE, NEW_TOPIC_REQ_NAME);
    if(IS_ERR(new_topic_cls)){

    }
    new_topic_cls->devnode = cls_devnode_setting; 
    device_create(new_topic_cls, NULL, MKDEV(major, 0), NULL, NEW_TOPIC_REQ_NAME); 
 
    pr_info("Device created on /dev/%s\n", NEW_TOPIC_REQ_NAME); 
 
    return SUCCESS; 
} 
 
static void __exit chardev_exit(void) 
{ 
    release_files();
    
    device_destroy(new_topic_cls, MKDEV(major, 0)); 
    class_destroy(new_topic_cls); 
    unregister_chrdev(major, NEW_TOPIC_REQ_NAME); 
    pr_info("Device /dev/%s has been unregistered.\n", NEW_TOPIC_REQ_NAME);
} 
 
static int new_topic_open(struct inode *inode, struct file *file) 
{ 
    static int counter = 0; 
    
    /*Read the 32-bit value of already_open through its address. Compute 
    * (already_open == CDEV_NOT_USED) ?  CDEV_EXCLUSIVE_OPEN : old and store result in already_open. 
    * The function returns old version of already_open. (I think, or else it will always be true)
    */
    if (atomic_cmpxchg(&already_open, CDEV_NOT_USED, CDEV_EXCLUSIVE_OPEN)) 
        return -EBUSY; 
 
    try_module_get(THIS_MODULE); 
 
    return SUCCESS; 
} 
 
static int new_topic_release(struct inode *inode, struct file *file) 
{  
    atomic_set(&already_open, CDEV_NOT_USED); 
 
    module_put(THIS_MODULE); 
 
    return SUCCESS; 
} 
 
static ssize_t new_topic_read(struct file *filp, /* see include/linux/fs.h   */ 
                           char __user *buffer, /* buffer to fill with data */ 
                           size_t length, /* length of the buffer     */ 
                           loff_t *offset) 
{ 
    /* Number of bytes actually written to the buffer */ 
    int bytes_read = 0; 
    const char *msg_ptr = msg; 
 
    if (!*(msg_ptr + *offset)) { /* we are at the end of message */ 
        *offset = 0; /* reset the offset */ 
        return 0; /* signify end of file */ 
    } 
 
    msg_ptr += *offset; 
 
    /* Actually put the data into the buffer */ 
    while (length && *msg_ptr) { 
        put_user(*(msg_ptr++), buffer++); 
        length--; 
        bytes_read++; 
    } 
 
    *offset += bytes_read; 
 
    /* Most read functions return the number of bytes put into the buffer. */ 
    return bytes_read; 
} 
 
/* Called when a process writes to dev file: echo "hi" > /dev/psipc/new_topic */ 
static ssize_t new_topic_write(struct file *filp, const char __user *buff, size_t len, loff_t *off) 
{ 
    int i, created_sub, path_len=0, buf_size, msg_len; 
    char *dir;
 
    /*
    Check on the number of topics when writing on new_topic
    if(MAX_SUB_DIR == topics_counter) return;
    else ...;
    */

    pr_info("new_topic_write(%p,%p,%ld)", filp, buff, len); 
 
    for (i = 0; i < len && i < BUF_LEN; i++) 
        get_user(msg[i], buff + i);

    msg_len = i;
    pr_info("Written: %s\n", msg);
    msg[i-1] = '\0';
    //msg[buf_size-1] = '\0';

    //create new topic
    path_len += strlen(TOPICS_DIR);
    path_len += strlen(msg);
    pr_info("WRITE: path total len %d, sub_dir len %d\n", path_len, strlen(msg));
    if(!(dir = (char*)kmalloc(path_len, GFP_KERNEL))){
        pr_alert("ERROR_W_KM: cannot allocate memory for %s\n", msg);
        return -ENOMEM;
    }
    strcpy(dir, TOPICS_DIR);
    strcat(dir, msg);

    //create exchange node for subdirectory
    struct exchange_node_s *elem;
    elem = (struct exchange_node_s*)kmalloc(sizeof(*elem), GFP_KERNEL);
    if(elem==NULL){
        pr_alert("ERROR_W: cannot allocae exchange node\n");
        return msg_len;
    }
    elem->dir_name = dir;
    
    for(i = 0; i < NUM_SPECIAL_FILES; i++){
        char *path = (char*)kmalloc(path_len + strlen(files[i]), GFP_KERNEL);
        strcpy(path, dir);
        strcat(path, files[i]);
        pr_info("CREATE: %s\n", path);

        created_sub = register_chrdev(0, path, fops[i]);
        if(created_sub<0){
            pr_alert("ERROR_W: Cannot create directory /dev/%s\n", path);
        }
        struct class *cls = class_create(THIS_MODULE, path);
        if(IS_ERR(cls)){
            pr_alert("ERROR_W: cannot create class for /dev/%s\n", path);
        }
        if(i==0 || i==2){//subscribe + nr_signal files
            cls->devnode = cls_set_writeOnly_permission;
        }else if(i==1){ //subscribers_list files
            cls->devnode = cls_set_readOnly_permission;
        }else{
            cls->devnode = cls_devnode_setting; 
        }
        elem->devices[i] = MKDEV(created_sub, 0);
        device_create(cls, NULL, elem->devices[i], NULL, path); 
        elem->file_dev_cls[i] = *cls;
    }
    INIT_LIST_HEAD(&(elem->subscribers_list_head));
    list_add(&(elem->list), &topicsHead);

    msg[0] = '\0';

    pr_info("CREATE_W: Device created on /dev/%s\n", dir);

    display_list();
    
    return msg_len; 
} 

static void release_files(void){
    int n_topics, n_files;
    struct list_head *ptr, *ptr2, *temp, *temp2;
    struct exchange_node_s *entry, *entry_temp;

    if(!list_empty(&topicsHead)){
        entry = list_first_entry_or_null(&topicsHead, struct exchange_node_s, list);

        if(entry == NULL){
            pr_alert("No topic to delete!\n");
            return;
        }

        list_for_each_safe(ptr, temp, &topicsHead){
            entry_temp = list_entry(ptr, struct exchange_node_s, list);
            if(entry_temp!=NULL){
                if(!list_empty(&(entry_temp->subscribers_list_head))){
                    list_for_each_safe(ptr2, temp2, &(entry_temp->subscribers_list_head)){
                        list_del(ptr2);
                    }
                }else{
                    pr_alert("No pid list to free\n");
                }
                pr_info("All pid freed\n");
                for(n_files=0; n_files < NUM_SPECIAL_FILES; n_files++){
                    char *str = (char*)kmalloc(strlen(entry_temp->dir_name) + strlen(files[n_files]), GFP_KERNEL);
                    strcpy(str, entry_temp->dir_name);
                    strcat(str, files[n_files]);
                    device_destroy(&(entry_temp->file_dev_cls[n_files]), entry_temp->devices[n_files]);
                    class_destroy(&(entry_temp->file_dev_cls[n_files]));
                    pr_info("DESTROY: %s/%s\n", str, files[n_files]);
                    unregister_chrdev(major, str);
                    kfree(str);
                }
                if(ptr!=NULL){
                    list_del(ptr);
                }else
                    pr_alert("ERROR_RELEASE: no pointer to free\n");
            }else
                pr_alert("ALERT:null entry\n");
        }
    }
}

static void display_list(void){
    int i=0;
    struct list_head *ptr;
    struct exchange_node_s *entry, *entry_ptr;

    entry = list_first_entry_or_null(&topicsHead, struct exchange_node_s, list);
    if(entry==NULL){
        pr_alert("ERROR: list is empty\n");
        return;
    }else{
    pr_info("-------BEGIN_LIST--------\n");
    list_for_each_entry(entry_ptr, &topicsHead, list){
        pr_info("Topic[%d]\n\tDir: %s\n", i++, entry_ptr->dir_name);
    }
    pr_info("------------END_LIST-------\n\n");
    }
}

static void display_pid_list(struct list_head *head){
    struct subscribers_pid_s *ptr;
    int i=0;

    pr_info("-------PID-LIST------\n");
    list_for_each_entry(ptr, head, list){
        pr_info("Pid[%d]: %d\n", i, ptr->pid);
    }
    pr_info("---------END_PID------\n\n");
}

static ssize_t subscribe_write(struct file *filp, const char __user *buff, size_t len, loff_t *off){
    int i, msg_len;
    char *dentry;
    struct exchange_node_s *node;
    struct subscribers_pid_s* pid_node;
 
    for (i = 0; i < len && i < BUF_LEN; i++) 
        get_user(msg[i], buff + i);

    msg_len = i;
    pr_info("Written: %s\n", msg);
    msg[i-1] = '\0';

    pid_node = (struct subscribers_pid_s*)kmalloc(sizeof(struct subscribers_pid_s), GFP_KERNEL);
    if(pid_node==NULL){
        pr_alert("Huston abbiamo un problema\n");
        return msg_len;
    }
    pid_node->pid = pro_atoi(msg);
    if(pid_node->pid <0){
        pr_alert("ERROR: %s is not a pid\n", msg);
        return msg_len;
    }

    dentry = filp->f_path.dentry->d_parent->d_iname;
    pr_info("Dentry to search: %s\n", dentry),
    node = search_node(dentry);
    if(node==NULL){
        pr_alert("Huston abbiamo un secondo problema\n");
        return msg_len;
    }
    list_add(&(pid_node->list), &(node->subscribers_list_head));
    pr_info("Added pid node to list\n");

    display_pid_list(&(node->subscribers_list_head));

    msg[0] = '\0';
    
    return msg_len; //remember to return nr written bytes
}

static ssize_t subs_list_read(struct file *filp, char __user *buffer, size_t length, loff_t *offset){
    int bytes_read = 0; 
    const char *msg_ptr = msg; 
 
    if (!*(msg_ptr + *offset)) {
        *offset = 0;
        return 0; 
    } 
 
    msg_ptr += *offset; 

    while (length && *msg_ptr) { 
        put_user(*(msg_ptr++), buffer++); 
        length--; 
        bytes_read++; 
    } 
 
    *offset += bytes_read; 
  
    return bytes_read; 
}
static ssize_t signal_nr_write(struct file *filp, const char __user *buff, size_t len, loff_t *off){return 0;}
static ssize_t endpoint_write(struct file *filp, const char __user *buff, size_t len, loff_t *off){return 0;}
static int subscribe_open(struct inode *inode, struct file *file){
    //spin_lock(&(file->spinlock)); //best not using spinlocks, semaphore are better coz it's okay if the execution is preempted
    try_module_get(THIS_MODULE);

    return SUCCESS;
}

static int subs_list_open(struct inode *inode, struct file *file){
    if (atomic_cmpxchg(&subscribers_list_already_open, CDEV_NOT_USED, CDEV_EXCLUSIVE_OPEN)) 
        return -EBUSY; 
    try_module_get(THIS_MODULE);
    return SUCCESS;
}
static int signal_nr_open(struct inode *inode, struct file *file){return -1;}
static int endpoint_open(struct inode *inode, struct file *file){return -1;}
static int subscribe_release(struct inode *inode, struct file *file){
    //spin_unlock(&(file->spinlock));//not use spinlocks, use semaphore
    module_put(THIS_MODULE);
    return SUCCESS;
}  

static int subs_list_release(struct inode *inode, struct file *file){
    atomic_set(&subscribers_list_already_open, CDEV_NOT_USED);
    module_put(THIS_MODULE);
    return SUCCESS;
}
static int signal_nr_release(struct inode *inode, struct file *file){return -1;}
static int endpoint_release(struct inode *inode, struct file *file){return -1;}

static struct exchange_node_s* search_node(char *dir){
    char *path;
    struct exchange_node_s *ptr;

    path = (char*)kmalloc(strlen(TOPICS_DIR) + strlen(dir), GFP_KERNEL);
    strcpy(path, TOPICS_DIR);
    strcat(path, dir);
    pr_info("Search for dentry %s\n", path);
    list_for_each_entry(ptr, &topicsHead, list){
        if(strcmp(ptr->dir_name, path)==0){
            pr_info("Node found!\n");
            return ptr;
        }
    }
    return NULL;
}

static int pro_atoi(char *s){
    int n=0, i;

    for(i=0; s[i]!='\0'; i++){
        if(s[i]<'0'  || s[i]>'9'){
            pr_alert("%s is not a pid\n", s);
            return -1;
        }
        n = n*10 + (s[i] - '0');
    }
    return n;
}
 
module_init(chardev_init); 
module_exit(chardev_exit); 
 
MODULE_LICENSE("GPL");
