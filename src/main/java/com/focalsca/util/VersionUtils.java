package com.focalsca.util;

import java.util.regex.Pattern;

public class VersionUtils {

    private static final Pattern SAFE_ID = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]*");
    private static final Pattern SAFE_VERSION = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._+-]*");
    private static final Pattern SAFE_COORDINATE =
            Pattern.compile(SAFE_ID.pattern() + ":" + SAFE_ID.pattern() + ":" + SAFE_VERSION.pattern());

    public static boolean isSafeVersion(String version) {
        return version != null && SAFE_VERSION.matcher(version).matches();
    }

    public static int majorVersion(String version) {
        try {
            return Integer.parseInt(version.split("[.\\-]")[0]);
        } catch (NumberFormatException e) {
            return -1;
        }
    }
}
