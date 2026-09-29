package com.focalsca.util;

public class VersionUtils {
    public static int majorVersion(String version) {
        try {
            return Integer.parseInt(version.split("[.\\-]")[0]);
        } catch (NumberFormatException e) {
            return -1;
        }
    }
}
