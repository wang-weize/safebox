#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <openssl/md5.h>
#define SAFEPATH "/home/wwz/safeBox"

char password[80], cmd1[80], cmd2[80];
char cwd[1024]; // filepath now

void convertUnCharToStr(char* str, unsigned char* UnChar, int ucLen){
	int i = 0;
	for(i = 0; i <ucLen; i++){
		//Format the input str, each unsigned char conversion character occupies two positions%x write input%X write input
		sprintf(str + i * 2, "%02x", UnChar[i]);
	}
}

int md5Cal(char * passwd)
{
    MD5_CTX ctx;
    unsigned char outmd[16];
    int i=0;
 
    memset(outmd,0,sizeof(outmd));
    MD5_Init(&ctx);
    MD5_Update(&ctx,passwd,strlen(passwd));
    MD5_Final(outmd,&ctx);
	char outmd32[33] = "\0";
	convertUnCharToStr(outmd32, outmd, strlen(outmd));
	// printf("%s\n", outmd32);
	if (strncmp(outmd32, "cdb9612161cc513f3b338e43ffa2daf4", 32) != 0){
		// printf("debug1\n");
		return -1;
	} 
	// printf("debug2\n");
    return 0;
}

void printIntro(){
	printf("-------------------------------------------------------------------------------------\n");
	printf("safebox program introductions:\n");
	printf("h                       :print this introduction.\n");
	printf("ls                      :check the file list in the safe box. (i.e. ls)\n");
	printf("in  [path/]filename     :copy file into safebox. (i.e. cp path/filename /home/wwz/safeBox)\n");
	printf("out [path/]filename     :copy file from safebox. (i.e. cp /home/wwz/safeBox/filename path/filename)\n");
	printf("del filename            :delete file in safebox. (i.e. rm filename)\n");
	printf("exit                    :exit the program.\n");
	printf("-------------------------------------------------------------------------------------\n");
}

void getFileName(char *dirPath){
	DIR *dir = opendir(dirPath);
	if (dir == NULL){
		printf("%s\n", strerror(errno));
		return;
	}
	chdir(dirPath);
	struct dirent *ent;
	while ((ent = readdir(dir)) != NULL){
		if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0){
			continue;
		}
		struct stat st;
		stat(ent->d_name, &st);
		if (S_ISDIR(st.st_mode)){
			getFileName(ent->d_name);
		}
		else{
			printf("%s\n", ent->d_name);
		}
	}
	closedir(dir);
	chdir("..");
}

int copyFile(char *from, char *to){
	int in = -1, out = -1, flag;
	char buffer[1024];

	chdir(cwd);

	printf("copy from %s to %s\n", from, to);

	in = open(from, S_IWUSR);
	if (in == -1){
		printf("open file %s failed!\n", from);
		return -1;
	}

	out = creat(to, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
	if (out == -1){
		printf("create file %s failed!\n", to);
		return -1;
	}

	// copy file content
	while ((flag = read(in, buffer, 1024)) > 0){
		write(out, buffer, flag);
	}

	close(in);
	close(out);

	return 0;
}

int is_dir_exist(const char *dir_path){
	if (dir_path == NULL){
		return -1;
	}
	if (opendir(dir_path) == NULL){
		return -1;
	}
	return 0;
}
 
// look for safebox dir.
int initialBox(){
	int judge = is_dir_exist(SAFEPATH);
	if (judge == 0){
		printf("find safeBox at /home/wwz/safeBox\n");
		return 0;
	}
	else if (judge == -1){
		printf("creating safeBox at /home/wwz/safeBox\n");
		int result = mkdir(SAFEPATH, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
		if (result == 0){
			printf("successfully create safeBox\n");
			return 0;
		}
		else{
			printf("create safeBox failure!!!\n");
			return -1;
		}
	}
	else{
		printf("wrong safeBox route!!!\n");
		return -1;
	} 
}

// check the password
int checkPassword(){
	int hashnum = 0;
	printf("Please enter the password: ");
	scanf("%s", password);
	if(md5Cal(password) == 0){
		printf("\n\tWelcome to safe manager!\n");
		return 0;
	}
	else{
		return -1;
	}
}

int main(int argc, char *argv[]){

	char *from, *to, *name;
	if(initialBox() != 0){
		return -1;
	}
	if(checkPassword()){
		printf("Wrong password!\n");
		return -1;
	}
	
	// getcwd()会将当前的工作目录绝对路径复制到参数buf 所指的内存空间
	getcwd(cwd, 1024);

	printIntro();
	while (1){
		fflush(stdin); // 清空缓冲区

		printf(">>> ");
		scanf("%s", cmd1);

		if (strcmp(cmd1, "help") == 0 || strcmp(cmd1, "h") == 0){ // print help information
			printIntro();
		}
		else if (strcmp(cmd1, "in") == 0){ // copy file to safebox
			scanf("%s", cmd2);
			from = cmd2;
			to = (char *)malloc(sizeof(char) * 80);
			strcpy(to, SAFEPATH);
			name = strrchr(from, '/'); // 在参数 str 所指向的字符串中搜索最后一次出现字符 c（一个无符号字符）的位置
			if (name == NULL){ // cmd is relative path
				strcat(to, "/");
				strcat(to, from);
			}
			else
				strcat(to, name);

			if (copyFile(from, to) == -1)
				printf("copy file failed!\n");
			else
				printf("copy file successfully!\n");

			free(to);
			to = NULL;
		}
		else if (strcmp(cmd1, "out") == 0){ // copy file from safebox
			scanf("%s", cmd2);
			to = cmd2;
			from = (char *)malloc(sizeof(char) * 80);
			strcpy(from, SAFEPATH);
			name = strrchr(to, '/');
			if (name == NULL){
				strcat(from, "/");
				strcat(from, to);
			}
			else
				strcat(from, name);

			printf("copy from %s to %s\n", from, to);

			if (copyFile(from, to) == -1)
				printf("copy file failed!\n");
			else
				printf("copy file successfully!\n");

			free(from);
			from = NULL;
		}
		else if (strcmp(cmd1, "del") == 0){ // delete file in safebox
			scanf("%s", cmd2);
			name = cmd2;
			from = (char *)malloc(sizeof(char) * 80);
			strcpy(from, SAFEPATH);
			strcat(from, "/");
			strcat(from, name);

			printf("delete file %s.\n", from);

			if (remove(from) == 0)
				printf("delete successfully!\n");
			else
				printf("delete failed!\n");
		}
		else if (strcmp(cmd1, "ls") == 0){
			getFileName(SAFEPATH);
		}
		else if (strcmp(cmd1, "exit") == 0)
			break;
		else
			goto wrong;

		continue;

	wrong:
		printf("Invalid syntax. Use 'h' or 'help' for help\n");
	}

	return 0;
}
