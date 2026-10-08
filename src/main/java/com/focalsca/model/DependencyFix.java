package com.focalsca.model;

import lombok.Getter;

@Getter
public class DependencyFix {

    private final Dependency original;
    private final String newVersion;

    public DependencyFix(Dependency original, String newVersion) {
        this.original = original;
        this.newVersion = newVersion;
    }

}
