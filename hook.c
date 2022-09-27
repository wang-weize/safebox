#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/unistd.h>
#include <linux/utsname.h>
#include <asm/pgtable.h>
#include <linux/kallsyms.h>
#include <linux/proc_fs.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/uaccess.h> 
#include <linux/rtc.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/fs_struct.h>
#include <linux/limits.h> 
#include <linux/time.h>
#include <linux/timex.h>
#include <linux/rtc.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("hook syscalls");

#define SAFEPATH "/home/wwz/safeBox"
#define COMMANDNAME "safe_manager"
#define MAX_LENGTH 256
#define MY_FILE "/home/wwz/safebox_log"

/*
The asmlinkage tag is one other thing that we should observe about this simple function.
This is a #define for some gcc magic that tells the compiler that 
the function should not expect to find any of its arguments in registers (a common optimization), 
but only on the CPU's stack. 
Recall our earlier assertion that system_call consumes its first argument, 
the system call number, 
and allows up to four more arguments that are passed along to the real system call. 
system_call achieves this feat simply by leaving its other arguments (which were passed to it in registers) on the stack. 
All system calls are marked with the asmlinkage tag, so they all look to the stack for arguments.
*/
typedef asmlinkage long (*orig_openat_t)(struct pt_regs *regs);
typedef asmlinkage long (*orig_rename_t)(struct pt_regs *regs);
typedef asmlinkage long (*orig_unlinkat_t)(struct pt_regs *regs);
typedef asmlinkage long (*orig_mkdir_t)(struct pt_regs *regs);
unsigned long sys_call_table_addr = 0;

orig_openat_t old_openat = NULL; // 用于保存原系统调用函数openat地址
orig_rename_t old_rename = NULL;
orig_unlinkat_t old_unlinkat = NULL;
orig_unlinkat_t old_mkdir = NULL;
unsigned int level;
// 多个页表项可以对应一个物理页面，因而支持共享内存
// 每个pte_t指向一个物理页的地址
// 在64位的x86平台，4.17及以上的内核中，采用了新的调用约定，
// 只使用struct pt_regs结构体指针这一个参数，即时解析出所需的参数，然后再传递到真正的系统调用处理函数中
pte_t *pte;


char * simplifyPath(char * path){
    unsigned int len = strlen(path);
    char *ret = (char *)kmalloc(sizeof(char) * (len + 1), GFP_KERNEL);
	int top = 0;
	int i, j;
    memset(ret, 0, sizeof(char) * (len + 1));
    ret[top++] = '/';
    for(i=0; i<len; i++){
        if(path[i] == '/' && ret[top - 1] == '/'){
            continue;
        }
        if(path[i] == '.'){
            int cnt = 0;
            while(path[i] == '.'){
                cnt++;
                i++;
            }
            i--;
            if(cnt > 2){
                for(j=0; j<cnt; j++){
                    ret[top++] = '.'; 
                }
            }else if(cnt == 2){
                if((i+1 < len && path[i+1] != '/') || (i > 1 &&path[i-2] != '/')){
                    ret[top++] = '.';
                    ret[top++] = '.';
                }else if(top > 1){
                    top--;
                    while(ret[top -1] != '/'){
                        top--;
                    }
                }
            }else if((cnt == 1 && i+1 < len && path[i+1] != '/')|| path[i-1] != '/'){
                ret[top++] = '.';
            }
            continue;
        }
        ret[top++] = path[i];
    }
    while(ret[top - 1] == '/' && top > 1){
        top--;
    }
    ret[top] = '\0';

    return ret;
}

// rename hook: from comm->pwd and path to fullpath
void get_fullpath_renamehook(char*fullpath, char* path_pwd, char* rpath){
	char *tmppath = (char*)kmalloc(MAX_LENGTH,GFP_KERNEL);
	if(strncmp(rpath, "/", 1) == 0){
		strcpy(fullpath, rpath);
	}
	else{
		strcpy(tmppath, path_pwd);
		strcat(tmppath, "/");
		strcat(tmppath, rpath);
		// printk("func: tmp is %s \n", tmppath);
		strcpy(fullpath, simplifyPath(tmppath));
		// printk("func: full is %s \n", fullpath);
	}
}

// 获得本地时间写入日志
int get_time_str(char *output)
{
    struct timex  txc;
    struct rtc_time tm;

    /* 获取当前的UTC时间 */
    do_gettimeofday(&(txc.time));

    /* 把UTC时间调整为本地时间 */
    txc.time.tv_sec -= sys_tz.tz_minuteswest * 60;

    /* 算出时间中的年月日等数值到tm中 */
    rtc_time_to_tm(txc.time.tv_sec,&tm);

    return sprintf(output, "%04d-%02d-%02d %02d:%02d:%02d"
        ,tm.tm_year+1900
        ,tm.tm_mon+1
        ,tm.tm_mday
        ,tm.tm_hour
        ,tm.tm_min
        ,tm.tm_sec);
}

// 遍历dentry树，将完整文件所在目录绝对路径存放到path中
void get_path_from_dentry(char *path, struct dentry *dentry) {
	char *buf = (char*)kmalloc(MAX_LENGTH,GFP_KERNEL);
	if (strcmp(dentry->d_name.name,"/") == 0) {
		strcpy(path,dentry->d_name.name);
		return;
	}

	strcpy(path,dentry->d_name.name);
	while ((dentry = dentry->d_parent) != NULL) {
		strcpy(buf,dentry->d_name.name);
		if (strcmp(buf,"/") != 0) {
			strcat(buf,"/"); // 追加到结尾
		}
		strcat(buf,path);
		strcpy(path,buf);
		if (strcmp(dentry->d_name.name,"/") == 0) {
			break;
		}
	}
}

// pt_regs: 在执行该系统调用时，用户态下的CPU寄存器在核心态的栈中的保存情况
// asmlinkage: 当函数前面有这个标签时，编译器编译出的可执行程序就会认为是按内核接口的调用约定对这个函数进行调用的，而不是用户态约定
// 内核接口调用约定见下
/* The Linux/x86-64 kernel expects the system call parameters in
   registers according to the following table:
    syscall number  rax
    arg 1    rdi
    arg 2    rsi
    arg 3    rdx
    arg 4    r10
    arg 5    r8
    arg 6    r9
......
*/
// 重载openat
asmlinkage long hooked_openat(struct pt_regs *regs) {
	char *name = (char*)kmalloc(MAX_LENGTH,GFP_KERNEL); // 内核分配内存 (size,mode)
	char *path = (char*)kmalloc(MAX_LENGTH,GFP_KERNEL); 
	char *simplifypath = (char*)kmalloc(MAX_LENGTH,GFP_KERNEL); 
	unsigned char buf[MAX_LENGTH]="\0";
	char localtime[25]="\0";
	mm_segment_t old_fs;
	struct file* file=NULL;
    struct kstat *stat;
	loff_t pos; 
	
	// int openat(int dirfd, const char *pathname, int flags);
	// si对应系统调用第二个参数pathname
	// strncpy_from_user: Copies a NUL-terminated string from userspace to kernel space.
	strncpy_from_user(name,(char*)regs->si,MAX_LENGTH);

	// 自旋锁，与task_unlock搭配使用
	task_lock(current);

	// absolute path: find '/' at pathmame[0]
	if (strncmp(name,"/",1) == 0) {
		strcpy(path,name);
	}
	// relative path
	// 如果dirfd的值是AT_FDCWD，pathname则是相对于进程当前工作目录的相对路径，此时等同于open
	else if ((int)regs->di == AT_FDCWD) {
		struct dentry *parent_dentry = current->fs->pwd.dentry;
		get_path_from_dentry(path,parent_dentry);
		//strcpy(path,parent_dentry->d_name.name);
		if (strcmp(path,"/") != 0) {
			strcat(path,"/");
		}
		strcat(path,name); // path里是文件路径
	}
	else {
		goto end; // dirfd指向的目录暂时无法获取
	}
	
	simplifypath = simplifyPath(path);
	if (strncmp(simplifypath, SAFEPATH, strlen(SAFEPATH) ) == 0) {
		// printk("wwz debug: to find the SAFEPATH, we get the true path %s. \n", path);
		if (strncmp(current->comm,COMMANDNAME,strlen(COMMANDNAME)-1) != 0) {
			printk("[hook mod] Find openat operation to safeBox. The path is %s by process %s \n",simplifypath,current->comm); // 这里comm里面是什么？
			// O_RDWR<02>;: 读写打开
			// O_CREAT<0100>;: 文件不存在则创建，需要mode_t，not fcntl
			file = filp_open(MY_FILE,O_RDWR|O_CREAT,0777); // 最终权限是755
            if (file==NULL)
			{
                printk("[hook mod] error occured while opening file %s, exiting...\n", MY_FILE);
                return -1;
            }
			
			get_time_str(localtime);
			sprintf(buf,"Find openat operation to safeBox. The path is %s by process %s. ------%s\n", simplifypath, current->comm, localtime);
			old_fs = get_fs();
			set_fs(KERNEL_DS); // 改变kernel对内存地址检查的处理方式
			stat =(struct kstat *) kmalloc(sizeof(struct kstat),GFP_KERNEL);
			vfs_stat(MY_FILE,stat);
			pos = stat->size; 
			// pos：返回数据写入后的文件指针
			vfs_write(file, buf, strlen(buf), &pos);
			set_fs(old_fs);
			filp_close(file, NULL);
			kfree(name);
			kfree(path);
			kfree(simplifypath);
			task_unlock(current);
			return -1;
		}
	}

end:
	kfree(name);
	kfree(path);
	kfree(simplifypath);
	task_unlock(current);
	return old_openat(regs);
}

// hook: int rename(const char *oldpath,const char *newpath)
// hook: int renameat(int oldfd, const char *oldname, int newfd, const char *newname);     
asmlinkage long hooked_rename(struct pt_regs *regs) {
	char *dst = (char*)kmalloc(MAX_LENGTH,GFP_KERNEL);
	char *src = (char*)kmalloc(MAX_LENGTH,GFP_KERNEL);
	char *dst_fullpath = (char*)kmalloc(MAX_LENGTH,GFP_KERNEL);
	char *src_fullpath = (char*)kmalloc(MAX_LENGTH,GFP_KERNEL);
	char *path = (char*)kmalloc(MAX_LENGTH,GFP_KERNEL);
	unsigned char buf[MAX_LENGTH]="\0";
	char localtime[25]="\0";
	mm_segment_t old_fs;
	struct file* file=NULL;
    struct kstat *stat;
	loff_t pos; 
	struct dentry *parent_dentry = current->fs->pwd.dentry;
	strncpy_from_user(dst,(char*)regs->si,MAX_LENGTH);
	strncpy_from_user(src,(char*)regs->di,MAX_LENGTH);
	
	
	get_path_from_dentry(path,parent_dentry);
	get_fullpath_renamehook(dst_fullpath, path, dst);
	get_fullpath_renamehook(src_fullpath, path, src);
	// printk("fulldst: %s\n", dst_fullpath);
	// printk("fullsrc: %s\n", src_fullpath);
	
	if(strstr(dst_fullpath, SAFEPATH)||strstr(src_fullpath, SAFEPATH))
	{
		if (strncmp(current->comm,COMMANDNAME,strlen(COMMANDNAME)-1) != 0)
		{
            printk("[hook mod] Find rename operation to safeBox. The path is %s, src:%s, dst:%s by process %s\n", 
			path, src_fullpath, dst_fullpath, current->comm);
			file = filp_open(MY_FILE,O_RDWR|O_CREAT,0777);
            if (file==NULL)
			{
                printk("[hook mod] error occured while opening file %s, exiting...\n", MY_FILE);
                return -1;
            }
			get_time_str(localtime);
			sprintf(buf,"Find rename operation to safeBox. The path is %s, src:%s, dst:%s by process %s ------%s\n", 
			path, src_fullpath, dst_fullpath, current->comm, localtime);
			old_fs = get_fs();
			set_fs(KERNEL_DS);
			stat =(struct kstat *) kmalloc(sizeof(struct kstat),GFP_KERNEL);
			vfs_stat(MY_FILE,stat);
			pos = stat->size; 
			vfs_write(file, buf, strlen(buf), &pos);
			set_fs(old_fs);
			filp_close(file, NULL);
			kfree(path);
			kfree(dst);
			kfree(src);
			kfree(dst_fullpath);
			kfree(src_fullpath);
			return -1;
		}
	}	
	kfree(path);
    kfree(dst);
	kfree(src);
	kfree(dst_fullpath);
	kfree(src_fullpath);
	return old_rename(regs);
}

// hook: do_unlinkat(int dfd, const char __user *pathname)
asmlinkage long hooked_unlinkat(struct pt_regs *regs) {
	char *name = (char*)kmalloc(MAX_LENGTH,GFP_KERNEL);
	char *path = (char*)kmalloc(MAX_LENGTH,GFP_KERNEL);
	char *simplifypath = (char*)kmalloc(MAX_LENGTH,GFP_KERNEL); 
	unsigned char buf[MAX_LENGTH]="\0";
	char localtime[25]="\0";
	mm_segment_t old_fs;
	struct file* file=NULL;
    struct kstat *stat;
	loff_t pos; 

	strncpy_from_user(name,(char*)regs->si,MAX_LENGTH); // si: pathname

	task_lock(current);

	//absolute path
	if (strncmp(name,"/",1) == 0) {
		strcpy(path,name);
	}
	//relative path
	else if ((int)regs->di == AT_FDCWD) {
		struct dentry *parent_dentry = current->fs->pwd.dentry;
		get_path_from_dentry(path,parent_dentry);
		//strcpy(path,parent_dentry->d_name.name);
		if (strcmp(path,"/") != 0) {
			strcat(path,"/");
		}
		strcat(path,name);
	}
	else {
		goto end; // 和openat一样，解决不了dirfd问题
	}
	
	simplifypath = simplifyPath(path);
	if (strncmp(simplifypath,SAFEPATH,strlen(SAFEPATH)) == 0) {
		if (strncmp(current->comm,COMMANDNAME,strlen(COMMANDNAME)-1) != 0) {
			printk("[hook mod] Find unlinkat operation to safeBox. The path is %s by process %s\n",simplifypath,current->comm);
            file = filp_open(MY_FILE,O_RDWR|O_CREAT,0777);
            if (file==NULL)
			{
                printk("[hook mod] error occured while opening file %s, exiting...\n", MY_FILE);
                return -1;
            }
			get_time_str(localtime);
			sprintf(buf,"Find unlinkat operation to safeBox. The path is %s by process %s ------%s\n", simplifypath, current->comm, localtime);
			old_fs = get_fs();
			set_fs(KERNEL_DS);
			stat =(struct kstat *) kmalloc(sizeof(struct kstat),GFP_KERNEL);
			vfs_stat(MY_FILE,stat);
			pos = stat->size; 
			vfs_write(file, buf, strlen(buf), &pos);
			set_fs(old_fs);
			filp_close(file, NULL);

			kfree(name);
			kfree(path);
			kfree(simplifypath);
			task_unlock(current);
			return -1;
		}
	}

end:
	kfree(name);
	kfree(path);
	kfree(simplifypath);
	task_unlock(current);
	return old_unlinkat(regs);
}

asmlinkage long hooked_mkdir(struct pt_regs *regs) {
	char *name = (char*)kmalloc(MAX_LENGTH,GFP_KERNEL); // 内核分配内存 (size,mode)
	char *path = (char*)kmalloc(MAX_LENGTH,GFP_KERNEL); 
	char *simplifypath = (char*)kmalloc(MAX_LENGTH,GFP_KERNEL); 
	unsigned char buf[MAX_LENGTH]="\0";
	char localtime[25]="\0";
	mm_segment_t old_fs;
	struct file* file=NULL;
    struct kstat *stat;
	loff_t pos; 
	
	// int openat(int dirfd, const char *pathname, int flags);
	// si对应系统调用第二个参数pathname
	// strncpy_from_user: Copies a NUL-terminated string from userspace to kernel space.
	strncpy_from_user(name,(char*)regs->di,MAX_LENGTH);
	printk("pathname mkdir: %s\n", name);

	// 自旋锁，与task_unlock搭配使用
	task_lock(current);

	// absolute path: find '/' at pathmame[0]
	if (strncmp(name,"/",1) == 0) {
		strcpy(path,name);
	}
	// relative path
	// 如果dirfd的值是AT_FDCWD，pathname则是相对于进程当前工作目录的相对路径，此时等同于open
	else {
		struct dentry *parent_dentry = current->fs->pwd.dentry;
		get_path_from_dentry(path,parent_dentry);
		//strcpy(path,parent_dentry->d_name.name);
		if (strcmp(path,"/") != 0) {
			strcat(path,"/");
		}
		strcat(path,name); // path里是文件路径
	}

	printk("path: %s\n", path);
	simplifypath = simplifyPath(path);
	if (strncmp(simplifypath, SAFEPATH, strlen(SAFEPATH) ) == 0) {
		// printk("wwz debug: to find the SAFEPATH, we get the true path %s. \n", path);
		if (strncmp(current->comm,COMMANDNAME,strlen(COMMANDNAME)-1) != 0) {
			printk("[hook mod] Find mkdir operation to safeBox. The path is %s by process %s \n",simplifypath,current->comm); // 这里comm里面是什么？
			// O_RDWR<02>;: 读写打开
			// O_CREAT<0100>;: 文件不存在则创建，需要mode_t，not fcntl
			file = filp_open(MY_FILE,O_RDWR|O_CREAT,0777); // 最终权限是755
            if (file==NULL)
			{
                printk("[hook mod] error occured while opening file %s, exiting...\n", MY_FILE);
                return -1;
            }
			
			get_time_str(localtime);
			sprintf(buf,"Find mkdir operation to safeBox. The path is %s by process %s. ------%s\n", simplifypath, current->comm, localtime);
			old_fs = get_fs();
			set_fs(KERNEL_DS); // 改变kernel对内存地址检查的处理方式
			stat =(struct kstat *) kmalloc(sizeof(struct kstat),GFP_KERNEL);
			vfs_stat(MY_FILE,stat);
			pos = stat->size; 
			// pos：返回数据写入后的文件指针
			vfs_write(file, buf, strlen(buf), &pos);
			set_fs(old_fs);
			filp_close(file, NULL);
			kfree(name);
			kfree(path);
			kfree(simplifypath);
			task_unlock(current);
			return -1;
		}
	}

	kfree(name);
	kfree(path);
	kfree(simplifypath);
	task_unlock(current);
	return old_mkdir(regs);
}

// Linux内核中所有的系统调用都是放在一个叫做sys_call_table的内核数组中，数组的值就表示这个系统调用服务程序的入口地址
static int obtain_sys_call_table_addr(unsigned long * sys_call_table_addr) {
	int ret = 1;
	unsigned long temp_sys_call_table_addr;
 
	temp_sys_call_table_addr = kallsyms_lookup_name("sys_call_table"); // 不用教材的方法，使用内核符号导出地址
	
	if (0 == sys_call_table_addr) {
		ret = -1;
		goto cleanup;
	}
	
	printk("Found sys_call_table: %p", (void *) temp_sys_call_table_addr); // 内核使用printk打印，%p用于打印指针
	*sys_call_table_addr = temp_sys_call_table_addr;
		
cleanup:
	return ret;
}
 
static int hooked_init(void) {
	int ret = -1;
    printk("+ Loading hook_mkdir module\n");
	ret = obtain_sys_call_table_addr(&sys_call_table_addr);
    if(ret != 1){
		printk("- unable to locate sys_call_table\n");
		return 0;
	}
    printk("+ found sys_call_table at %08lx!\n", sys_call_table_addr); //unsigned long: %lx
 
    old_openat = ((orig_openat_t *)(sys_call_table_addr))[__NR_openat]; // __NR_openat为openat的系统调用号
    old_rename = ((orig_rename_t *)(sys_call_table_addr))[__NR_rename]; 
    old_unlinkat = ((orig_unlinkat_t *)(sys_call_table_addr))[__NR_unlinkat]; 
	old_mkdir = ((orig_mkdir_t *)(sys_call_table_addr))[__NR_mkdir]; 
	
    pte = lookup_address((unsigned long)sys_call_table_addr, &level); // 查找虚拟地址所在的页表地址
 
    set_pte_atomic(pte, pte_mkwrite(*pte)); // pte_mkwrite将页表置为可写
 
    printk("+ unprotected kernel memory page containing sys_call_table\n");
 

    ((unsigned long * ) (sys_call_table_addr))[__NR_openat]= (unsigned long) hooked_openat;
    ((unsigned long * ) (sys_call_table_addr))[__NR_rename]= (unsigned long) hooked_rename;
    ((unsigned long * ) (sys_call_table_addr))[__NR_unlinkat]= (unsigned long) hooked_unlinkat;
	((unsigned long * ) (sys_call_table_addr))[__NR_mkdir]= (unsigned long) hooked_mkdir;
	
    printk("+ sys_openat hooked!\n");
    printk("+ sys_rename hooked!\n");
    printk("+ sys_unlinkat hooked!\n");
	printk("+ sys_mkdir hooked!\n");
	
    set_pte_atomic(pte, pte_clear_flags(*pte, _PAGE_RW));

	
    return 0;
}

 
static void hooked_exit(void) {
	pte = lookup_address((unsigned long)sys_call_table_addr, &level);
	
    set_pte_atomic(pte, pte_mkwrite(*pte));
    	
	// 系统调用入口恢复
   
    ((unsigned long * ) (sys_call_table_addr))[__NR_openat] = (unsigned long) old_openat;
    ((unsigned long * ) (sys_call_table_addr))[__NR_rename] = (unsigned long) old_rename;
	((unsigned long * ) (sys_call_table_addr))[__NR_unlinkat] = (unsigned long) old_unlinkat;
	((unsigned long * ) (sys_call_table_addr))[__NR_mkdir] = (unsigned long) old_mkdir;
    set_pte_atomic(pte, pte_clear_flags(*pte, _PAGE_RW));

               
    printk("+ Unloading hook.ko\n");
}

module_init(hooked_init);
module_exit(hooked_exit);
