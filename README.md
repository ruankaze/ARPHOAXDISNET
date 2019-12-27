# ARPHOAXDISNET
开发语言JAVA，使用ARP欺骗，实现局域网断网。

其 result 下。

注：主要用于吾蹭WIFI，防止尔等共享网速。
注：当然JAVA环境还是要的。
注：第一步必需要做，然后运行第三步或第四步即可。

1. 文件夹 exe 中（必须要做的事，否则运行异常，3/4）。
	1.1 Jpcap.dll 放入JDK的BIN目录下。
	1.2 jpcap.jar 是开发时必须的JAR包。
	1.3 WinPcap_4_1_3.exe 直接安装，一直下一步即可。

2. 文件夹 logback 中，分别都是日志信息。
	主要日志：可以在 logback/log_info.log 中查看程序执行的info日志。

3. 批处理文件 ARPHOAXDISNET.bat。
	它会打开CMD界面，主要用于直观查看程序运行的每一步信息（如果出现乱码，请前往第二步查看）。

4. 程序 ARPHOAXDISNET.exe。
	运行后，可以在任务栏看到，程序将在后台默默执行。

5. 非断网IP配置文件 ArpNotDisnet.txt。
	输入不断网的IP地址，每行输入一个ip地址。（可以在cmd输入ipconfig查看自己的ip地址）

6. CMD 命令。
	Systeminfo 查看系统信息
	wmic nic list brief 查看网卡信息
