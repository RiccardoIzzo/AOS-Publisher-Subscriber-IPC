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
static int subscribe_release(struct inode*, struct file*);                       
static int signal_nr_release(struct inode*, struct file*);
static int endpoint_release(struct inode*, struct file*);

static void release_files(void);

static int init_sub_dir(int);   
 
#define SUCCESS 0 
#define ROOT_DIR "psipc"
#define NEW_TOPIC_REQ_NAME "psipc/new_topic" /* Dev name as it appears in /proc/devices   */ 
#define TOPICS_DIR "psipc/topics/"
#define BUF_LEN 100 /* Max length of the message from the device */ 
#define MAX_SUB_DIR 10
#define NUM_SPECIAL_FILES 4

const char* files[] = {"/subscribe", "/subscribes_list", "/signal_nr", "/endpoint"};
 
static int major; /* it will be the same one because they're all of the same type*/
static int topics_counter = 0;

enum { 
    CDEV_NOT_USED = 0, 
    CDEV_EXCLUSIVE_OPEN = 1, 
}; 
 
/* Is device open? Used to prevent multiple access to device */ 
static atomic_t already_open = ATOMIC_INIT(CDEV_NOT_USED); 
 
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
    .write = subscribe_write,
    .open = subscribe_open,
    .release = subscribe_release,
};

static struct file_operations subscribers_list_fops = {
    .read = subs_list_read,
    //cannot be open from user mode
}; 

static struct file_operations signal_nr_fops = {
	.write = signal_nr_write,
	.open = signal_nr_open,
	.release = signal_nr_release,
};

static struct file_operations endpoint_fops = {
	.write = endpoint_write,
	.open = endpoint_open,
	.release = endpoint_release,
};

typedef struct exchange_node_s{
    //file_operations subscribe_fops, subscribers_list_fops, signal_nr_fops, endpoint_fops;
	struct class file_dev_cls[4];
	char *dir_name;
}exchange_node_t;

static exchange_node_t node_array[MAX_SUB_DIR];

//to set device permissions
static char *cls_devnode_setting(struct device *dev, umode_t *mode){
    if(mode!=NULL){
        *mode = (umode_t)0666;
    }
    return NULL;
}

static int __init chardev_init(void) 
{ 
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
    pr_info("Device /dev/%s has been unregistered,\n", NEW_TOPIC_REQ_NAME);
} 
 
/* Methods */ 
 
/* Called when a process tries to open the device file, like 
 * "sudo cat /dev/chardev" 
 */ 
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
 
/* Called when a process closes the device file. */ 
static int new_topic_release(struct inode *inode, struct file *file) 
{ 
    /* We're now ready for our next caller */ 
    atomic_set(&already_open, CDEV_NOT_USED); 
 
    /* Decrement the usage count, or else once you opened the file, you will 
     * never get get rid of the module. 
     */ 
    module_put(THIS_MODULE); 
 
    return SUCCESS; 
} 
 
/* Called when a process, which already opened the dev file, attempts to 
 * read from it. 
 */ 
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
    int i, created_sub, path_len=0, buf_size; 
    char *dir;
 
    /*
    Check on the number of topics when writing on new_topic
    if(MAX_SUB_DIR == topics_counter) return;
    else ...;
    */

    pr_info("new_topic_write(%p,%p,%ld)", filp, buff, len); 

    /*if(len > BUF_LEN)
        buf_size = BUF_LEN;
    else
        buf_size = len;
    
    if(copy_from_user(msg, buff, buf_size)){
        pr_alert("Can't copy from user\n");
        return -EFAULT;
    }*/
 
    for (i = 0; i < len && i < BUF_LEN; i++) 
        get_user(msg[i], buff + i);

    pr_info("Written: %s\n", msg);
    msg[i-1] = '\0';
    //msg[buf_size-1] = '\0';

    //create new topic
    path_len += strlen(TOPICS_DIR);
    path_len += strlen(msg);
    pr_info("WRITE: path total len %d, sub_dir len %d\n", path_len, strlen(msg));
    if(!(dir = (char*)kmalloc(path_len + 1, GFP_KERNEL))){
        pr_alert("ERROR_W_KM: cannot allocate memory for %s\n", msg);
        return -ENOMEM;
    }
    strcpy(dir, TOPICS_DIR);
    strcat(dir, msg);

    //create exchange node for subdirectory
    exchange_node_t elem;
    elem.dir_name = dir;
    
    for(i = 0; i < NUM_SPECIAL_FILES; i++){
        char *path = (char*)kmalloc(path_len + strlen(files[i]), GFP_KERNEL);
        strcpy(path, dir);
        strcat(path, files[i]);
        pr_info("CREATE: %s\n", path);

        created_sub = register_chrdev(0, path, &subscribe_fops);
        if(created_sub<0){
            pr_alert("ERROR_W: Cannot create directory /dev/%s\n", path);
        }
        struct class *cls = class_create(THIS_MODULE, path);
        if(IS_ERR(cls)){
            pr_alert("ERROR_W: cannot create class for /dev/%s\n", path);
        }
        cls->devnode = cls_devnode_setting; 
        device_create(cls, NULL, MKDEV(created_sub, 0), NULL, path); 
        elem.file_dev_cls[i] = *cls;
    }

    node_array[topics_counter++] = elem;
    //memset(msg, '\0', BUF_LEN);
    msg[0] = '\0';
    //to implement
    //TODO: save all cls in file_dev_cls
    //TODO: remove devices files in all topic folders, for now "sudo rm -r psipc/"
    //Check: msg buffer error sometimes?

    pr_info("CREATE_W: Device created on /dev/%s\n", dir); 
    

    return i; 
} 

static void release_files(void){
    int n_topics, n_files;
    for(n_topics = 0; n_topics < topics_counter; n_topics++){
        for(n_files = 0; n_files < NUM_SPECIAL_FILES; n_files++){
            char *str = (char*)kmalloc(strlen(node_array[n_topics].dir_name) + strlen(files[n_files]), GFP_KERNEL);
            strcpy(str, node_array[n_topics].dir_name);
            strcat(str, files[n_files]);
            device_destroy(&(node_array[n_topics].file_dev_cls[n_files]), MKDEV(major, 0)); 
            class_destroy(&(node_array[n_topics].file_dev_cls[n_files])); 
            pr_info("%s\n", str, files[n_files]);
            unregister_chrdev(major, str); 
        }
        
        //pr_info("Device /dev/%s has been unregistered,\n", NEW_TOPIC_REQ_NAME);
    }
}

static ssize_t subscribe_write(struct file *filp, const char __user *buff, size_t len, loff_t *off){return 0;}
//static ssize_t signal_nr_write(struct file *filp, const char __user *buff, size_t len, loff_t *off){}
//static ssize_t endpoint_write(struct file *filp, const char __user *buff, size_t len, loff_t *off){}
static int subscribe_open(struct inode *inode, struct file *file){return SUCCESS;}
//static int signal_nr_open(struct inode *inode, struct file *file){}
//static int endpoint_open(struct inode *inode, struct file *file){}
static int subscribe_release(struct inode *inode, struct file *file){return SUCCESS;}                      
//static int signal_nr_release(struct inode *inode, struct file *file){}
//static int endpoint_release(struct inode *inode, struct file *file){}


static int init_sub_dir(int buffer_len){
	return SUCCESS;
}

 
module_init(chardev_init); 
module_exit(chardev_exit); 
 
MODULE_LICENSE("GPL");
