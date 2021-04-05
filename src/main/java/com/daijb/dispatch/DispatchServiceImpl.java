package com.daijb.dispatch;

import com.mchange.v2.c3p0.ComboPooledDataSource;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.annotation.Bean;
import org.springframework.context.event.EventListener;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import javax.sql.DataSource;
import java.beans.PropertyVetoException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.*;

/**
 * @author daijb
 * @date 2021/2/24 12:54
 */
@Service
public class DispatchServiceImpl implements DispatchService {

    private static final Logger logger = LoggerFactory.getLogger(DispatchServiceImpl.class);

    private List<String> allAssetIps = new ArrayList<>();

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @EventListener(ApplicationReadyEvent.class)
    public void onApplicationReadyEvent(ApplicationReadyEvent event) {
        startThreadFunc0(null, null, true);
    }

    public void startThreadFunc(String addr, Integer areaId) {
        Timer timer = new Timer();
        // 每五分钟执行
        timer.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                try {
                    logger.info("------------------");
                    logger.info("addr : " + addr + ", area id : " + areaId);
                    startThreadFunc0(addr, areaId, false);
                } catch (Throwable throwable) {
                    logger.error("task timer schedule failed ", throwable);
                }
            }
        }, 1000, 1000 * 60);
    }

    public void startThreadFunc0(String addr, Integer areaId, boolean isFirst) {

        if (System.getProperty("os.name").toLowerCase().contains("window")) {
            return;
        }
        if (addr == null || addr.trim().isEmpty()) {
            addr = "https://192.168.9.43:5144";
        }
        searchAsset(areaId);
        int len = 1;
        if (isFirst) {
            len = 3;
        }
        for (int i = 0; i < len; i++) {
            try {
                sendMalware(addr);
                sendTi(addr);
                sendFileCheck(addr);
                sendHttp(addr);
                sendNetThreat(addr);
            } catch (UnknownHostException e) {
                logger.error("发送恶意代码事件失败 ： ", e);
            }
        }
    }

    /**
     * {
     * "SrcRealIP":"",
     * "SHA1":"22bff02f4581f6893524e91c3f0bf65fe7d113d2",
     * "L7P":"HTTP",
     * "Time":"1614591453000",
     * "rID":"622f15ff5023bced451a95372fdc2f76",
     * "Direction":"0",
     * "URL":"192.168.3.12/zentao/product-ajaxGetDropMenu-3-testcase-browse-.html",
     * "Name":"product-ajaxGetDropMenu-3-testcase-browse-.html",
     * "TrtFmly":0,
     * "EngTrtType":[
     * <p>
     * ],
     * "ResponseCode":200,
     * "SrcPort":"51111",
     * "EngTrtName":[
     * <p>
     * ],
     * "EngID":[
     * <p>
     * ],
     * "FileSource":"0",
     * "EngTrtFmly":[
     * <p>
     * ],
     * "EngTrtDesc":[
     * <p>
     * ],
     * "DstPort":"80",
     * "SrcIP":"172.16.2.130",
     * "TrtType":0,
     * "FlowID":"75416766d5394e3258fdd0ce3177d9f9-0001",
     * "VLANID":1344,
     * "SHA256":"78f7751aa414410f399aa04f0870d777420feeafabb72b8a40336d2003dafd85",
     * "FileType":"html",
     * "TrtLevel":0,
     * "DstIP":"192.168.3.12",
     * "DstMAC":"bc:3f:8f:63:6c:80",
     * "EngTrtLevel":[
     * <p>
     * ],
     * "SrcMAC":"14:a0:f8:9b:5c:82",
     * "MD5":"4c1544c8656e1e0f9451f25694edc82d"
     * }
     */
    private void sendFileCheck(String host) throws UnknownHostException {
        logger.info("开始发送文件检测事件......");

        int max = allAssetIps.size(), min = 1;
        String srcIP = allAssetIps.get((int) (System.currentTimeMillis() % (max - min) + min));
        String dstIP = allAssetIps.get((int) (System.currentTimeMillis() % (max - min) + min));
        JSONArray item = new JSONArray();

        JSONObject data = new JSONObject();

        JSONObject headers = new JSONObject();
        headers.put("LogVer", 2);
        headers.put("LogType", LogType.csp_filechecking.name());
        headers.put("rHost", InetAddress.getLocalHost().getHostAddress());
        headers.put("rTime", System.currentTimeMillis());
        data.put("headers", headers);

        JSONArray body = new JSONArray();

        JSONObject bodyItem = new JSONObject();

        bodyItem.put("SrcRealIP", "");
        bodyItem.put("SHA1", "37c58a0d2c039a3b33bbfeb3f06158fb23e8c711");
        bodyItem.put("L7P", "HTTP");
        bodyItem.put("Time", "1614591453000");
        bodyItem.put("rID", UUID.randomUUID().toString().replaceAll("-", ""));
        bodyItem.put("Direction", 0);
        bodyItem.put("URL", "192.168.3.12/zentao/product-ajaxGetDropMenu-3-testcase-browse-.html");
        bodyItem.put("Name", "product-ajaxGetDropMenu-3-testcase-browse-.html");
        bodyItem.put("TrtFmly", 0);
        bodyItem.put("EngTrtType", new JSONArray());
        bodyItem.put("ResponseCode", 200);
        bodyItem.put("SrcPort", 51111);
        bodyItem.put("EngTrtFmly", new JSONArray());
        bodyItem.put("EngTrtDesc", new JSONArray());
        bodyItem.put("DstPort", 80);
        bodyItem.put("SrcIP", getRandomIp());
        bodyItem.put("TrtType", 0);
        bodyItem.put("FlowID", UUID.randomUUID().toString().replaceAll("-", ""));
        bodyItem.put("VLANID", "1344");
        bodyItem.put("SHA256", "f4c0d9d35f3ff617ed77d5d558600e140ca49634eae56a19a402e90755768820");
        bodyItem.put("FileType", "html");
        bodyItem.put("TrtLevel", 4);
        bodyItem.put("DstIP", dstIP);
        bodyItem.put("DstMAC", "bc:3f:8f:63:6c:80");
        JSONArray trtLevel = new JSONArray();
        trtLevel.add(4);
        bodyItem.put("EngTrtLevel", trtLevel);
        bodyItem.put("SrcMAC", "14:a0:f8:9b:5c:82");
        bodyItem.put("MD5", "62b0a8771a4c8920acba780f9480652e");


        body.add(bodyItem);
        data.put("body", body);

        item.add(data);

        logger.info(LogType.csp_filechecking.name() + "send data json : " + item);
        String[] commands = new String[]{"curl", "--connect-timeout", "10", "-i", "-H", "\"Content-Type: application/json; charset=UTF-8\"", "-d", item.toJSONString(), "-k1", host};
        try {
            SystemUtil.execute(commands);
        } catch (Exception e) {
            logger.error("exec command failed : ", e);
        }
    }

    /**
     * {
     * "ReqType":"application/octet-stream",
     * "SrcPort":53279,
     * "User-Agent":"MicroMessenger Client",
     * "Time":1614591195513,
     * "Host":"extshort.weixin.qq.com",
     * "DstPort":80,
     * "Method":"POST",
     * "RespLength":229,
     * "SrcIP":"192.168.7.171",
     * "StatusCode":200,
     * "URL":"/mmtls/00001e98",
     * "RespType":"application/octet-stream",
     * "FlowID":"c5173a063a566908e87720695e4141c7-0001",
     * "VLANID":3923,
     * "ReqLength":490,
     * "Proxy":"no",
     * "DstIP":"112.65.193.167",
     * "DstMAC":"bc:3f:8f:63:6c:80",
     * "TrafficSource":"eth1",
     * "Protocol":"HTTP",
     * "SrcMAC":"00:0e:c6:b9:d4:81"
     * }
     */
    private void sendHttp(String host) throws UnknownHostException {
        logger.info("开始发送http事件......");

        int max = allAssetIps.size(), min = 1;
        String srcIP = allAssetIps.get((int) (System.currentTimeMillis() % (max - min) + min));
        String dstIP = allAssetIps.get((int) (System.currentTimeMillis() % (max - min) + min));
        JSONArray item = new JSONArray();

        JSONObject data = new JSONObject();

        JSONObject headers = new JSONObject();
        headers.put("LogVer", 2);
        headers.put("LogType", LogType.csp_http.name());
        headers.put("rHost", InetAddress.getLocalHost().getHostAddress());
        headers.put("rTime", System.currentTimeMillis());
        data.put("headers", headers);

        JSONArray body = new JSONArray();

        JSONObject bodyItem = new JSONObject();

        bodyItem.put("ReqType", "application/octet-stream");
        bodyItem.put("SrcPort", 53279);
        bodyItem.put("User-Agent", "MicroMessenger Client");
        bodyItem.put("Time", "1614591195513");
        bodyItem.put("Host", "extshort.weixin.qq.com");
        bodyItem.put("DstPort", 80);
        bodyItem.put("Method", "POST");
        bodyItem.put("RespLength", 329);
        bodyItem.put("SrcIP", getRandomIp());
        bodyItem.put("StatusCode", 200);
        bodyItem.put("URL", "/mmtls/00001e98");
        bodyItem.put("RespType", "application/octet-stream");
        bodyItem.put("FlowID", UUID.randomUUID().toString().replaceAll("-", ""));
        bodyItem.put("VLANID", 3923);
        bodyItem.put("ReqLength", 1026);
        bodyItem.put("Proxy", "no");
        bodyItem.put("DstIP",dstIP);
        bodyItem.put("DstMAC", "bc:3f:8f:63:6c:80");
        bodyItem.put("TrafficSource", "eth1");
        bodyItem.put("Protocol", "HTTP");
        bodyItem.put("SrcMAC", "00:0e:c6:b9:d4:81");


        body.add(bodyItem);
        data.put("body", body);

        item.add(data);
        logger.info(LogType.csp_http.name() + "send data json : " + item);
        String[] commands = new String[]{"curl", "--connect-timeout", "10", "-i", "-H", "\"Content-Type: application/json; charset=UTF-8\"", "-d", item.toJSONString(), "-k1", host};
        try {
            SystemUtil.execute(commands);
        } catch (Exception e) {
            logger.error("exec command failed : ", e);
        }
    }

    /**
     * {
     * "Time":"1614591225000",
     * "rID":"34941",
     * "SrcIP":"192.168.7.220",
     * "Name":"41",
     * "VLANID":3748,
     * "FlowID":"0847a3e2f5eff231bb27ca0c7fc42ad8-0001",
     * "Desc":"{"TDOMAIN":"pub.idqqimg.com","DESC":"malware"}",
     * "DstIP":"192.168.3.8",
     * "DstMAC":"bc:3f:8f:63:6c:80",
     * "Level":"2",
     * "TrafficSource":"eth1",
     * "RepType":"4",
     * "SrcMAC":"54:ab:3a:6a:d4:ba"
     * }
     */
    private void sendTi(String host) throws UnknownHostException {
        logger.info("开始发送威胁情报事件......");

        int max = allAssetIps.size(), min = 1;
        String srcIP = allAssetIps.get((int) (System.currentTimeMillis() % (max - min) + min));
        String dstIP = allAssetIps.get((int) (System.currentTimeMillis() % (max - min) + min));
        JSONArray item = new JSONArray();

        JSONObject data = new JSONObject();

        JSONObject headers = new JSONObject();
        headers.put("LogVer", 2);
        headers.put("LogType", LogType.csp_ti.name());
        headers.put("rHost", InetAddress.getLocalHost().getHostAddress());
        headers.put("rTime", System.currentTimeMillis());
        data.put("headers", headers);

        JSONArray body = new JSONArray();

        JSONObject bodyItem = new JSONObject();
        bodyItem.put("Time", System.currentTimeMillis());
        bodyItem.put("rID", UUID.randomUUID().toString().replaceAll("-", ""));
        bodyItem.put("SrcIP", getRandomIp());
        bodyItem.put("Name", "41");
        bodyItem.put("VLANID", 3748);
        bodyItem.put("FlowID", UUID.randomUUID().toString().replaceAll("-", ""));
        bodyItem.put("Desc", "\"{\"TDOMAIN\":\"pub.idqqimg.com\",\"DESC\":\"malware\"}\",");
        bodyItem.put("DstIP", dstIP);
        bodyItem.put("DstMAC", "bc:3f:8f:63:6c:80");
        bodyItem.put("Level", 5);
        bodyItem.put("TrafficSource", "eth1");
        bodyItem.put("RepType", "4");
        bodyItem.put("SrcMAC", "54:ab:3a:6a:d4:ba");

        body.add(bodyItem);
        data.put("body", body);

        item.add(data);
        logger.info(LogType.csp_ti.name() + "send data json : " + item);
        String[] commands = new String[]{"curl", "--connect-timeout", "10", "-i", "-H", "\"Content-Type: application/json; charset=UTF-8\"", "-d", item.toJSONString(), "-k1", host};
        try {
            SystemUtil.execute(commands);
        } catch (Exception e) {
            logger.error("exec command failed : ", e);
        }
    }

    private void sendMalware(String host) throws UnknownHostException {
        logger.info("开始发送恶意代码事件......");

        int max = allAssetIps.size(), min = 1;
        String srcIP = allAssetIps.get((int) (System.currentTimeMillis() % (max - min) + min));
        String dstIP = allAssetIps.get((int) (System.currentTimeMillis() % (max - min) + min));
        JSONArray item = new JSONArray();

        JSONObject data = new JSONObject();

        JSONObject headers = new JSONObject();
        headers.put("LogVer", 2);
        headers.put("LogType", LogType.csp_malware.name());
        headers.put("rHost", InetAddress.getLocalHost().getHostAddress());
        headers.put("rTime", System.currentTimeMillis());
        data.put("headers", headers);

        JSONArray body = new JSONArray();

        JSONObject bodyItem = new JSONObject();

        bodyItem.put("AlterType","BackDoor_spy");
        bodyItem.put("rID", UUID.randomUUID().toString().replaceAll("-", ""));
        bodyItem.put("FlowID", UUID.randomUUID().toString().replaceAll("-", ""));
        bodyItem.put("SrcMAC", "00:0c:29:de:85:9a");
        bodyItem.put("SrcIP", getRandomIp());
        bodyItem.put("SrcPort", 51486);
        bodyItem.put("DstMAC", "bc:3f:8f:63:6c:80");
        bodyItem.put("DstIP", dstIP);
        bodyItem.put("DstPort", 60782);
        bodyItem.put("L7P", "FTP");
        bodyItem.put("Name", "input/ce54ae052b80e39129627cf82d47cbab3fd6a988");
        bodyItem.put("FileType", "php");
        bodyItem.put("URL", "api.bangwo8.net/osp2016/gnapi/GetNotice.php?ClientID=309480784&Vendor=gnway&version=5.3.8.6&AuthCode=1f0aed857064f640e1ebb0c5381a6f85");
        bodyItem.put("MD5", "8061efe9b74523579cfb03cc7ce04b05");
        bodyItem.put("SHA1", "937b54ce5e77d36d85fbab586f282385de1cead3");
        bodyItem.put("SHA256", "1ab1c4642217ccd82b1b64df890291f7adc56cc0b7ef294e9fef0fc1e7286938");
        bodyItem.put("Direction", 0);
        bodyItem.put("TrtType", 0);
        bodyItem.put("TrtLevel", 4);
        bodyItem.put("EngID", Arrays.asList("Windows", "AV", "Windows", "Windows"));
        bodyItem.put("TrtFmly", 2);
        bodyItem.put("TrtName", "ADWARE/Adware.Gen");
        bodyItem.put("TrtDesc", "可疑广告弹窗软件Contains virus patterns of Adware ADWARE/Adware.Gen");

        body.add(bodyItem);
        data.put("body", body);

        item.add(data);

        logger.info(LogType.csp_malware.name() + "send data json : " + item);
        String[] commands = new String[]{"curl", "--connect-timeout", "10", "-i", "-H", "\"Content-Type: application/json; charset=UTF-8\"", "-d", item.toJSONString(), "-k1", host};
        try {
            SystemUtil.execute(commands);
        } catch (Exception e) {
            logger.error("exec command failed : ", e);
        }
    }

    /**
     * 发送网络威胁事件csp_netthreat
     * <p>
     * {
     * "SrcPort":3306,
     * "TrtID":4200305,
     * "Time":"1614591923011",
     * "DstPort":52827,
     * "rID":"",
     * "SrcIP":"192.168.9.148",
     * "Direction":0,
     * "TrtType":420,
     * "FlowID":"abcc25995cb61ab76242103440af1832",
     * "VLANID":0,
     * "TrtLevel":1,
     * "DstIP":"192.168.8.166",
     * "DstMAC":"84:c5:a6:f2:8e:56",
     * "TrtName":"MySQL Server respond OK",
     * "TrafficSource":"eth1",
     * "PtlType":"TCP",
     * "SrcMAC":"bc:3f:8f:63:6c:80",
     * "Dataflow":"BwAAAQAAAAIAAAABAAABCFAAAAIDZGVmEmluZm9ybWF0aW9uX3NjaGVtYQh0cmlnZ2VycwhUUklHR0VSUwxBQ1RJT05fR0VSUw1BQ1RJT05fVElNSU5HDUFDVElPTl9USU1JTkcMLQAYAAAA/QEAAAAABQAACv4AACIABQAAC/4AACIA"
     * }
     */
    private void sendNetThreat(String host) throws UnknownHostException {
        logger.info("开始发送网络威胁事件......");
        int max = allAssetIps.size(), min = 1;
        String srcIP = allAssetIps.get((int) (System.currentTimeMillis() % (max - min) + min));
        String dstIP = allAssetIps.get((int) (System.currentTimeMillis() % (max - min) + min));
        JSONArray item = new JSONArray();

        JSONObject data = new JSONObject();

        JSONObject headers = new JSONObject();
        headers.put("LogVer", 2);
        headers.put("LogType", DispatchService.LogType.csp_netthreat.name());
        headers.put("rHost", InetAddress.getLocalHost().getHostAddress());
        headers.put("rTime", System.currentTimeMillis());
        data.put("headers", headers);

        JSONArray body = new JSONArray();

        JSONObject bodyItem = new JSONObject();

        if (srcIP.length() % 2 == 0) {
            bodyItem.put("AlterType", "Tool_Muieblackcat");
        } else {
            bodyItem.put("AlterType", "Tunnel_HTTP");
        }
        if (dstIP.length() % 3 == 0) {
            bodyItem.put("AlterType", "Leak_ShellCode");
        }
        bodyItem.put("SrcPort", 3306);
        bodyItem.put("TrtID", 4200305);
        bodyItem.put("Time", "1614591923011");
        bodyItem.put("DstPort", 52827);
        bodyItem.put("rID", "");
        bodyItem.put("SrcIP", getRandomIp());
        bodyItem.put("Direction", 0);
        bodyItem.put("TrtType", 420);
        bodyItem.put("FlowID", UUID.randomUUID().toString().replaceAll("-", ""));
        bodyItem.put("VLANID", 0);
        bodyItem.put("TrtLevel", 4);
        bodyItem.put("DstIP", dstIP);
        bodyItem.put("DstMAC", "84:c5:a6:f2:8e:56");
        bodyItem.put("TrtName", "MySQL Server respond OK");
        bodyItem.put("TrafficSource", "eth1");
        bodyItem.put("PtlType", "TCP");
        bodyItem.put("SrcMAC", "bc:3f:8f:63:6c:80");
        bodyItem.put("Dataflow", "BwAAAQAAAAIAAAABAAABCFAAAAIDZGVmEmluZm9ybWF0aW9uX3NjaGVtYQh0cmlnZ2VycwhUUklHR0VSUwxBQ1RJT05fR0VSUw1BQ1RJT05fVElNSU5HDUFDVElPTl9USU1JTkcMLQAYAAAA");


        body.add(bodyItem);
        data.put("body", body);

        item.add(data);
        logger.info(LogType.csp_netthreat.name() + "send data json : " + item);
        String[] commands = new String[]{"curl", "--connect-timeout", "10", "-i", "-H", "\"Content-Type: application/json; charset=UTF-8\"", "-d", item.toJSONString(), "-k1", host};
        try {
            SystemUtil.execute(commands);
        } catch (Exception e) {
            logger.error("exec command failed : ", e);
        }
    }

    private void searchAsset(Integer areaId) {
        List<String> assetIps = new ArrayList<>();
        String querySql = "select * from asset ";
        if (areaId != null) {
            querySql = querySql + " where area_id ='" + areaId + "'";
        }
        logger.info("search query expr : " + querySql);
        List<Map<String, Object>> maps = jdbcTemplate.queryForList(querySql);
        for (Map<String, Object> asset : maps) {
            String assetIp = asset.get("asset_ip").toString();
            assetIps.add(getIps(assetIp));
        }
        this.allAssetIps.clear();
        this.allAssetIps = assetIps;
    }

    private String getIps(String addr) {
        // {"00:00:00:00:00:00":["192.192.192.192"]}
        int start = addr.indexOf("[") + 2;
        int end = addr.indexOf("]") - 1;
        return addr.substring(start, end);
    }

    @Bean(name = "dataSource")
    public DataSource dataSource() throws PropertyVetoException {
        ComboPooledDataSource ds = new ComboPooledDataSource();
        String os = System.getProperty("os.name").toLowerCase();
        String addr = "localhost";
        if (os.contains("windows")) {
            addr = "192.168.9.43";
        }
        logger.info("connect mysql addr : " + addr);
        ds.setDriverClass("com.mysql.cj.jdbc.Driver");
        ds.setJdbcUrl("jdbc:mysql://" + addr + "/csp");
        ds.setUser("root");
        ds.setPassword("Admin@123");
        ds.setMinPoolSize(1);
        ds.setMaxPoolSize(10);
        ds.setMaxIdleTime(120);
        ds.setIdleConnectionTestPeriod(60);
        ds.setTestConnectionOnCheckout(true);
        return ds;
    }


    /**
     * 随机生成国内IP地址
     *
     * @return
     */
    public String getRandomIp() {

        //ip范围
        int[][] range = {
                //36.56.0.0-36.63.255.255
                {607649792, 608174079},
                //61.232.0.0-61.237.255.255
                {1038614528, 1039007743},
                //106.80.0.0-106.95.255.255
                {1783627776, 1784676351},
                //121.76.0.0-121.77.255.255
                {2035023872, 2035154943},
                //123.232.0.0-123.235.255.255
                {2078801920, 2079064063},
                //139.196.0.0-139.215.255.255
                {-1950089216, -1948778497},
                //171.8.0.0-171.15.255.255
                {-1425539072, -1425014785},
                //182.80.0.0-182.92.255.255
                {-1236271104, -1235419137},
                //210.25.0.0-210.47.255.255
                {-770113536, -768606209},
                //222.16.0.0-222.95.255.255
                {-569376768, -564133889},
        };

        Random random = new Random();
        int index = random.nextInt(10);
        String ip = num2ip(range[index][0] + new Random().nextInt(range[index][1] - range[index][0]));
        return ip;
    }

    /**
     * 将十进制转换成ip地址
     *
     * @param ip
     * @return
     */
    private String num2ip(int ip) {
        int[] b = new int[4];
        String x = "";

        b[0] = (int) ((ip >> 24) & 0xff);
        b[1] = (int) ((ip >> 16) & 0xff);
        b[2] = (int) ((ip >> 8) & 0xff);
        b[3] = (int) (ip & 0xff);
        x = Integer.toString(b[0]) + "." + Integer.toString(b[1]) + "." + Integer.toString(b[2]) + "." + Integer.toString(b[3]);

        return x;
    }

}
