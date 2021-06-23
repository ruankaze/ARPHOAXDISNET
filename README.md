# ARPHOAXDISNET
开发语言JAVA，使用ARP欺骗，实现局域网断网。

注：主要用于蹭WIFI时，防止共享网速，嘿嘿。</br>
注：当然JAVA环境还是要的。</br>
注：默认不断自己电脑的网，ArpNotDisnet.txt 文件中可配置更多。</br>

说明：

1. arp.hoax.disnet.NzArpHoaxDisnet - 主程序入口

2. 文件夹 logback 中，分别都是日志信息。</br>
	主要日志：可以在 logback/log_info.log 中查看程序执行的info日志。
	
3. 非断网IP配置文件 ArpNotDisnet.txt。</br>
	输入不断网的IP地址，每行输入一个ip地址。（可以在cmd输入ipconfig查看自己的ip地址）</br>
	
4. CMD 命令。</br>
    systeminfo 查看系统信息</br>
    wmic nic list brief 查看网卡信息</br>

方式一：项目运行

注：ArpNotDisnet.txt 文件必须和项目目录同级，需要手动创建。</br>

1. 手动导入JAR包 - /result/exe/jpcap.jar。

2. 运行 NzArpHoaxDisnet - main 方法，即可。

方式二：exe 运行

注：第一步必需要做，然后运行第二步或第三步即可。</br>

1. 文件夹 exe 中（必须要做的事，否则运行异常，2/3）。</br>
	1.1 Jpcap.dll 放入JDK的BIN目录下。</br>
	1.2 WinPcap_4_1_3.exe 直接安装，一直下一步即可。</br>

2. 批处理文件 ARPHOAXDISNET.bat。</br>
	它会打开CMD界面，主要用于直观查看程序运行的每一步信息（如果出现乱码，请前往 logback 查看）。</br>

3. 程序 ARPHOAXDISNET.exe。</br>
	运行后，可以在任务栏看到，程序将在后台默默执行。</br>




