package com.daijb.dispatch;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author daijb
 * @date 2021/2/24 17:06
 */
@RestController
public class DispatchController {

    @Autowired
    private DispatchServiceImpl dispatchService;

    @RequestMapping(path = "/api/v1/dispatch",
            method = RequestMethod.GET,
            produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<String> getAutoConfigInfos(String addr, Integer areaId) throws Exception {
        if (addr == null || addr.trim().isEmpty()) {
            throw new Exception("addr is null.");
        }
        dispatchService.startThreadFunc(addr,areaId);
        return ResponseEntity.ok().build();
    }
}
