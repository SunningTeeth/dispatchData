package com.daijb.dispatch;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * @author daijb
 * @date 2021/2/24 12:53
 */
public class SystemUtil {

    private static final int DEFAULT_PROCESS_TIMEOUT = 10;

    public static List<String> execute(String command) throws Exception {
        return execute(command, new AtomicInteger());
    }

    public static List<String> execute(String command, AtomicInteger exitValue) throws Exception {
        Process process = Runtime.getRuntime().exec(command);
        return execute0(process, exitValue);
    }

    public static List<String> execute(String[] commands) throws Exception {
        return execute(commands, new AtomicInteger());
    }

    public static List<String> execute(String[] commands, AtomicInteger exitValue) throws Exception {
        Process process = Runtime.getRuntime().exec(commands);
        return execute0(process, exitValue);
    }

    private static List<String> execute0(Process process, AtomicInteger exitValue) throws Exception {
        List<String> result = new ArrayList<>();
        try (BufferedReader in = new BufferedReader(new InputStreamReader(process.getInputStream()));
             BufferedReader err = new BufferedReader(new InputStreamReader(process.getErrorStream()));) {
            String line;
            while ((line = in.readLine()) != null) {
                result.add(line);
            }
            while ((line = err.readLine()) != null) {
                result.add(line);
            }
        } finally {
            exitValue.set(destroyProcess(process));
        }
        return result;
    }

    public static int destroyProcess(Process process) {
        return destroyProcess(process, DEFAULT_PROCESS_TIMEOUT);
    }

    public static int destroyProcess(Process process, int waitSeconds) {
        if (process == null) {
            return 0;
        }
        try {
            process.waitFor(waitSeconds, TimeUnit.SECONDS);
        } catch (Throwable e) {
        }
        try {
            process.getInputStream().close();
        } catch (Throwable e) {
        }
        try {
            process.getOutputStream().close();
        } catch (Throwable e) {
        }
        try {
            process.getErrorStream().close();
        } catch (Throwable e) {
        }
        process.destroyForcibly();
        return process.exitValue();
    }
}
