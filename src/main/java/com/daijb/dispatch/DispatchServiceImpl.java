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
            len = 50;
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
        bodyItem.put("rID", UUID.randomUUID().toString().replaceAll("-", ""));
        bodyItem.put("FlowID", UUID.randomUUID().toString().replaceAll("-", ""));
        bodyItem.put("SrcMAC", "");
        bodyItem.put("SrcIP", srcIP);
        bodyItem.put("SrcPort", 0);
        bodyItem.put("DstMAC", "");
        bodyItem.put("DstIP", dstIP);
        bodyItem.put("DstPort", 0);
        bodyItem.put("L7P", "FTP");
        bodyItem.put("Name", "1.html");
        bodyItem.put("FileType", "html");
        bodyItem.put("URL", "192.168.3.188/api/v1/clusters/BlueSky/requests?to=end&page_size=10&fields=Requests&_=1613626876005");
        bodyItem.put("MD5", "62b0a8771a4c8920acba780f9480652e");
        bodyItem.put("SHA1", "37c58a0d2c039a3b33bbfeb3f06158fb23e8c711");
        bodyItem.put("SHA256", "f4c0d9d35f3ff617ed77d5d558600e140ca49634eae56a19a402e90755768820");
        bodyItem.put("Direction", 0);
        bodyItem.put("TrtType", 3);
        bodyItem.put("TrtLevel", 3);
        bodyItem.put("EngID", Arrays.asList("Windows", "AV", "Windows", "Windows"));
        bodyItem.put("TrtFmly", 2);
        bodyItem.put("TrtName", "ADWARE/Adware.Gen");
        bodyItem.put("TrtDesc", "可疑广告弹窗软件Contains virus patterns of Adware ADWARE/Adware.Gen");


        body.add(bodyItem);
        data.put("body", body);

        item.add(data);

        String[] commands = new String[]{"curl", "--connect-timeout", "10", "-i", "-H", "\"Content-Type: application/json; charset=UTF-8\"", "-d", item.toJSONString(), "-k1", host};
        try {
            SystemUtil.execute(commands);
        } catch (Exception e) {
            logger.error("exec command failed : ", e);
        }
    }

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
        bodyItem.put("FlowID", "44e5ce469a5e26e0055e1097f4aa2cc5-0001");
        bodyItem.put("Protocol", "HTTP");
        bodyItem.put("SrcIP", srcIP);
        bodyItem.put("SrcPort", 4088);
        bodyItem.put("DstIP", dstIP);
        bodyItem.put("DstPort", 80);
        bodyItem.put("Method", "GET");
        bodyItem.put("URL", "message/updateTime?tags=commontags&updateTime=d751713988987e9331980363e24189ce1513215818070");
        bodyItem.put("Host", "api.foxitreader.cn");
        bodyItem.put("User-Agent", "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET4.0C; .NET4.0E; InfoPath.3)");
        bodyItem.put("Proxy", "no");
        bodyItem.put("StatusCode", 200);
        bodyItem.put("RespLength", 1026);


        body.add(bodyItem);
        data.put("body", body);

        item.add(data);

        String[] commands = new String[]{"curl", "--connect-timeout", "10", "-i", "-H", "\"Content-Type: application/json; charset=UTF-8\"", "-d", item.toJSONString(), "-k1", host};
        try {
            SystemUtil.execute(commands);
        } catch (Exception e) {
            logger.error("exec command failed : ", e);
        }
    }

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
        bodyItem.put("rID", UUID.randomUUID().toString().replaceAll("-", ""));
        bodyItem.put("RepType", 3);
        bodyItem.put("Level", 3);
        bodyItem.put("Name", "rdata");
        bodyItem.put("SrcIP", srcIP);
        bodyItem.put("DstIP", dstIP);
        bodyItem.put("Desc", "{\"TIP\":" + dstIP + "}");

        body.add(bodyItem);
        data.put("body", body);

        item.add(data);

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
        bodyItem.put("rID", UUID.randomUUID().toString().replaceAll("-", ""));
        bodyItem.put("FlowID", UUID.randomUUID().toString().replaceAll("-", ""));
        bodyItem.put("SrcMAC", "00:0c:29:de:85:9a");
        bodyItem.put("SrcIP", srcIP);
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
        bodyItem.put("TrtLevel", 3);
        bodyItem.put("EngID", Arrays.asList("Windows", "AV", "Windows", "Windows"));
        bodyItem.put("TrtFmly", 2);
        bodyItem.put("TrtName", "ADWARE/Adware.Gen");
        bodyItem.put("TrtDesc", "可疑广告弹窗软件Contains virus patterns of Adware ADWARE/Adware.Gen");

        body.add(bodyItem);
        data.put("body", body);

        item.add(data);

        String[] commands = new String[]{"curl", "--connect-timeout", "10", "-i", "-H", "\"Content-Type: application/json; charset=UTF-8\"", "-d", item.toJSONString(), "-k1", host};
        try {
            SystemUtil.execute(commands);
        } catch (Exception e) {
            logger.error("exec command failed : ", e);
        }
    }

    /**
     * 发送网络威胁事件
     * curl --connect-timeout 10 -i -H "Content-Type: application/json; charset=UTF-8" -d '[{"headers":{"LogVer":2,"LogType":"csp_malware","rHost":"192.168.7.24","rTime":"1545190200000"},"body":[{"rID":"001c109d2b1a8c7e1412a7","FlowID":"001c109d2b1a8c7e1412a713ae0a8c57","SrcMAC":"","SrcIP":"192.168.5.2","SrcPort":"41075","DstMAC":"","DstIP":"192.168.5.2","DstPort":"80","L7P":"HTTP","Name":"1db6fa0c3661a57816a827d693f3c3f0d86570e7.bin","FileType":"exe","URL":"192.168.3.7/pe/1db6fa0c3661a57816a827d693f3c3f0d86570e7.bin","MD5":"edca6c38794e9fbf52093f297bf636d1","SHA1":"1db6fa0c3661a57816a827d693f3c3f0d86570e7","SHA256":"17a657c649c3c41a89cc71d0a5bfd389ee38887ee454b965e6c6e70c0bef03bc","Direction":"0","TrtType":0,"TrtLevel":3,"EngID":"AV","TrtFmly":9,"TrtName":"ADWARE/Adware.Gen","TrtDesc":" 可疑广告弹窗软件Contains virus patterns of Adware ADWARE/Adware.Gen","Time":"1545190200000"}]}]' -k1 https://192.168.9.162:5144
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

        bodyItem.put("rID", UUID.randomUUID().toString().replaceAll("-", ""));
        bodyItem.put("FlowID", UUID.randomUUID().toString().replaceAll("-", ""));
        bodyItem.put("SrcIP", srcIP);
        bodyItem.put("SrcPort", 53211);
        bodyItem.put("DstIP", dstIP);
        bodyItem.put("DstPort", 8080);
        bodyItem.put("Dataflow", "SElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmc");
        bodyItem.put("Direction", 1);
        bodyItem.put("PtlType", "TCP");
        bodyItem.put("TrtID", 5000003);
        bodyItem.put("TrtType", 69);
        bodyItem.put("TrtLevel", 3);
        bodyItem.put("TrtName", "针对火眼红队黑客工具利用检测(User32LogonProcesss)");


        body.add(bodyItem);
        data.put("body", body);

        item.add(data);

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
        List<Map<String, Object>> maps = jdbcTemplate.queryForList(querySql);
        for (Map<String, Object> asset : maps) {
            String assetIp = asset.get("asset_ip").toString();
            assetIps.add(getIps(assetIp));
        }
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

}
