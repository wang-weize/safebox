# safebox
System Software Course Design, SJTU IS415


![image](https://user-images.githubusercontent.com/45849124/192436326-5534566c-5a46-4a85-a2e2-6d9993eb9325.png)

## environment

Linux 4.18.0-25-generic (buildd@lcy01-amd64-025) cosmic

VMware® Workstation 16 Pro

Ubuntu 18.10

memory: 4GB
	
gcc version: 8.3.0 (Ubuntu 8.3.0-6ubuntu1~18.10.1

make version: GNU Make 4.2.1

## run

make

sudo insmod hook.ko

lsmod | grep -e hook
