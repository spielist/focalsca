package com.focalsca.model;

import lombok.Getter;

import java.util.Collections;
import java.util.List;

@Getter
public class ReachabilityResult {

    public enum Status {
        NOT_ANALYZED,
        REACHABLE,
        UNREACHABLE
    }

    public static ReachabilityResult notAnalyzed() {
        return new ReachabilityResult(Status.NOT_ANALYZED, Collections.emptyList(), Collections.emptyList());
    }

    public static ReachabilityResult unreachable(List<String> vulnerableMethods) {
        return new ReachabilityResult(Status.UNREACHABLE, vulnerableMethods, Collections.emptyList());
    }

    public static ReachabilityResult reachable(List<String> vulnerableMethods, List<String> reachableVia) {
        return new ReachabilityResult(Status.REACHABLE, vulnerableMethods, reachableVia);
    }

    private final Status status;
    private final List<String> vulnerableMethods;    // methods identified as vulnerable for this CVE
    private final List<String> reachableVia;         // entry points that reach the vulnerable method

    public ReachabilityResult(Status status, List<String> vulnerableMethods, List<String> reachableVia) {
        this.status = status;
        this.vulnerableMethods = vulnerableMethods;
        this.reachableVia = reachableVia;
    }

    public boolean isAnalyzed() { return status != Status.NOT_ANALYZED; }

    public boolean isReachable() { return status == Status.REACHABLE; }

}
