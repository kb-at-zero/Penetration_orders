# <center> 内网渗透测试命令合集 @KB-AT</center>
## *0x01 内网信息收集*
  
### Windows信息收集   
* **基本命令**  
`systeminfo  #查看本机信息与补丁`  
`tasklist /svc  #显示每个进程中的服务信息`   
`tasklist /S ip /U domain \username /P /V  #查看远程计算机tasklist`   
`netstat -ano  #查看端口开放`  
`net sessoin  #查看远程连接session（需要管理权限）`  
`net share  #共享目录`  
`cmdkey /l  查看保存登录凭据`  
`spn -l administrator spn  #记录`   
`set  #环境变量`  
`dsquery server  #查找目录中的AD DC/LDS实例`  
`dsquery computer  #查询所有计算机名出 windows 2003`  
`dir /s *.exe  #查找制定目录下及子目录下没隐藏文件`  
`schtasks /QUERY /fo LIST /v  #查看计划任务`   
`DRIVERQUERY  #查看安装的驱动`  
`wmic os get osarchitecture  #查看操作系统架构`   
`wmic logicaldisk get caption  #查看逻辑盘`  
`wmic product get name,version   #查看安装的软件信息`   
`wmic service list brief  #查看服务信息`   
`ver  #查看版本`   

* **用户信息**   
` query user || qwinsta  #查看当前在线用户`  
`net user   #查看本机用户`  
`whoami /all #查看Mandatory Label uac级别和sid号`  
`net localgroup administrators && whoami  #查看当前是不是属于管理组`   
`dsquery user  #查询目录中的用户`  
`net config workstation  #当前登录域 - 计算机名 - 用户名`  

* **域信息**  
`net view /domain #查看域用户`  
`net view & net group "domain computers" /domain #查看当前域计算机列表`  
`net view /domain #查看有几个域`  
`net view \\\\dc #查看dc域内共享文件`  
`net group /domain  #查看域里面的组`  
`net group "domain admins" /domain  #查看域管`  
`net localgroup administrators /domain  #查域管，是升级为域控时，本地账户也成为域管`  
`net group "domain controllers" /domain #查域控`  
`net time /domain #也可以查看域控`  
`net use \\\\域控(如pc.test.com) password /user:test.com\username #相当于这个账户登录域内主机，可访问域内资源`   
`ipconfig /all  #查看网卡信息，是否存在域`   
`nltest / dclist:xx #查看域控`  
`echo %logonserver%  #查看登陆域`   
`nltest /domain_trusts  #查看域信任信息`  

*  **网络信息**   
`ipconfig  #网卡信息`   
`arp -a   #ARP表`   
`route print  #路由表`   
`netstat -ano  #监听的端口`   
`hosts文件`      
`ipconfig /displaydns     #DNS缓存`
`Get-CimInstance -Namespace root/StandardCimv2 -ClassName MSFT_DNSClientCache  #DNS缓存`

* **防火墙**   
`netsh advfirewall show allprofiles  #查看防火墙信息`   
`netsh firewall show logging  #查看防火墙日志`   
`netsh advfirewall firewall show rule name=all  #防火墙规则`   
`netsh firewall show config   ##防火墙的配置`   
`netsh firewall show state   #防火墙状态`   

* **其他**   
`wmic qfe get Caption,Description,HotFixID,InstalledOn   #查看补丁情况`   
`wevtutil   #日志与事件信息`   
`reg   #注册表`   
`attrib +s +a +r +h filename / attrib +s +h filename     #创建系统隐藏文件`   

### Linux信息收集   
* 版本信息   
`uname -a     #所有版本`   
`uname -r     #内核版本信息`  
`uname -n     #系统主机名字`   
`uname -m     #Linux内核架构`   
`cat /proc/version     #查看内核信息`   
`cat /proc/cpuinfo     #查看cpu信息`   
`cat /etc/*-release  | cat /etc/issue   #发布信息`    
`hostname     #主机名`   
`df -a     #文件系统`   
`dmesg / /var/log/dmesg    #内核日志`   

* 用户和组  
`whoami    #当前用户`    
`id      #当前用户信息`  
`cat /etc/passwd     #查看系统所有用户`    
`cat /etc/group        #查看系统都有组`   
`cat /etc/shadow       #查看所有用户hash(需root)`   
`finger              #查询用户基本信息`   
`users  | who -a | /var/log/utmp  #当前登录的用户` 
`w    #目前登录的用户`   
`last | /var/log/wtmp    #登录过的用户`   
`lastlog  | /var/log/lastlog   #显示系统中所有用户最近一次登录信息`   
`cat /var/log/secure    #登录成功日志`   
`/var/log/faillog     #登录失败日志`   
`grep :0 /etc/passwd      #特权用户查看`   
`ls -l /etc/passwd       #查看passwd最后修改时间`   
`awk -F: 'length($2)==0 {print $1}' /etc/shadow        #查看是否存在空口令用户`   
`awk '/\$1|\$6/{print $1}' /etc/shadow       #查看远程登录的用户`   
`cat /etc/sudoers | grep -v "^#\|^$" | grep "ALL=(ALL)"       #查看具有sudo权限的用户`  
`cat /etc/sudoers     #可以使用sudo提升到root的用户（root）`   
`sudo -l        #列出目前用户可执行与无法执行的指令`   

* 环境信息   
`env    #系统环境信息`   
`set    #系统环境变量信息`   
`echo $PATH    #环境变量的路径信息`    
`history / ~/.bash_history    #打印历史命令`   
`pwd       #显示当前路径`    
`cat /etc/profile      #显示默认系统遍历`   
`cat /etc/shells        #显示可用shell`   

* 进程信息   
`ps aux      #显示进程信息`    
`top -c        #系统资源使用情况`   
`lsof -c $PID    #查看进程关联文件`   
`/proc/$PID/cmdline     #完整命令行信息 `  
`/proc/$PID/comm       #进程的命令名`    
`/proc/$PID/cwd          #进程当前工作目录的符号链接`    
`/proc/$PID/exe          #运行程序的符号链接`    
`/proc/$PID/environ     #进程的环境变量 `   
`/proc/$PID/fd           #进程打开文件的情况`    

* 服务信息   
 `cat /etc/inetd.conf       #由inetd管理的服务列表`    
`cat /etc/xinetd.conf       #由xinetd管理的服务列表`    
`cat /etc/exports            #nfs服务器的配置`   
`/var/log/mailog             #邮件信息`    
`sshd_config                  #ssh配置`   

* 计划任务   
`crontab -l -u %user%      #显示指定用户的计划任务`   
`/var/spool/cron/*`   
`/var/spool/anacron/*`    
`/etc/crontab`   
`/etc/anacrontab`    
`/etc/cron.*`   
`/etc/anacrontab`   
`/etc/rc.d/init.d/     #开机启动项`    

* 网络、路由和通信   
`ip addr show   |  /sbin/ifconfig -a      #列出网卡接口信息`
`cat /etc/network/interfaces               #列出网络接口信息`   
`arp -a       #查看系统arp表`    
`route / ip ro show       #路由信息`    
`cat /etc/resolv.conf      #查看dns信息`   
`netstat -an             #本地端口开放信息`    
`iptables -L               #列出iptables 配置规则`   
`cat /etc/services       #端口服务映射`  
`hostname     #主机名`   
`netstat -anltp | grep $PID       #查看进程端口情况`    

* 已安装的程序  
`rpm -qa --last      #Redhat`   
`yum list | grep installed      #CentOS`   
`ls -l /etc/yum.repos.d/`  
`dpkg -l               #Debian`   
`cat /etc/apt/sources.list          #Debian APT`   
`pkg_info                      #xBSD`   
`pkginfo                       #Solaris`   
`pacman -Q                 #Arch Linux`   

* 文件   
`find / -ctime +1 -ctime -5          #最近5天的文件`   

* 公私钥信息   
`~/.ssh`  
`/etc/ssh`   

* 日志   
`/var/log/boot.log`  
`/var/log/cron`    
`/var/log/faillog`  
`/var/log/lastlog`  
`/var/log/messages`  
`/var/log/secure`  
`/var/log/syslog`  
`/var/log/wtmp`  
`/var/run/utmp`  

*********************************
## *0x02 权限提升*   

