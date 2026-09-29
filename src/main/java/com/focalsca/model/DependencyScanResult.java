package com.focalsca.model;

import com.focalsca.scanner.FixVersionResult;
import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

@Getter
@Setter
public class DependencyScanResult {

    public enum ReachabilityStatus {
        NOT_ANALYZED,   // reachability analysis has not been run yet
        REACHABLE,      // at least one vulnerable method is reachable from an entry point
        UNREACHABLE,    // vulnerable methods exist but none are reachable
        UNUSED          // dependency is not referenced anywhere in the application bytecode
    }

    private final Dependency dependency;
    private final List<Vulnerability> vulnerabilities;

    private FixVersionResult sameMajorFix;
    private FixVersionResult crossMajorFix;

    private ReachabilityStatus reachabilityStatus = ReachabilityStatus.NOT_ANALYZED;

    public DependencyScanResult(Dependency dependency) {
        this.dependency = dependency;
        this.vulnerabilities = new ArrayList<>();
    }

    public DependencyScanResult(Dependency dependency, List<Vulnerability> vulnerabilities) {
        this.dependency = dependency;
        this.vulnerabilities = vulnerabilities;
    }

    public boolean hasVulnerabilities() {
        return !vulnerabilities.isEmpty();
    }

    public boolean isUnused() {
        return reachabilityStatus == ReachabilityStatus.UNUSED;
    }

    public boolean isReachable() {
        return reachabilityStatus == ReachabilityStatus.REACHABLE;
    }

    public Severity highestSeverity() {
        return vulnerabilities.stream()
                .map(Vulnerability::getSeverity)
                .min(Comparator.naturalOrder()) // CRITICAL < HIGH < MEDIUM < LOW in enum order
                .orElse(null);
    }

}
