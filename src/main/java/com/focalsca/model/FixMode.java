package com.focalsca.model;

public enum FixMode {

    NONE(false, false),
    VERIFY(true, false),              // resolve and scan the fix versions; change nothing
    APPLY(false, true),               // write the fix versions to the build files
    VERIFY_AND_APPLY(true, true);

    private final boolean verify;
    private final boolean apply;

    FixMode(boolean verify, boolean apply) {
        this.verify = verify;
        this.apply = apply;
    }

    public boolean verifies() { return verify; }
    public boolean applies() { return apply; }
    public boolean isEnabled() { return verify || apply; }

}
