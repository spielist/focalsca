package com.focalsca.scanner;

import com.focalsca.model.Severity;
import com.focalsca.model.Vulnerability;
import lombok.Getter;

import java.util.List;
import java.util.Map;
import java.util.StringJoiner;
import java.util.stream.Collectors;

@Getter
public class FixVersionResult {

    private final String version;
    private final Map<Severity, Integer> vulnerabilitiesBySeverity;

    public FixVersionResult(String version, List<Vulnerability> vulnerabilities) {
        this.version = version;
        this.vulnerabilitiesBySeverity = vulnerabilities.stream()
                .collect(Collectors.groupingBy(
                        Vulnerability::getSeverity,
                        Collectors.collectingAndThen(Collectors.counting(), Long::intValue)
                ));
    }

    public int getVulnerabilityCount() {
        return vulnerabilitiesBySeverity.values().stream().reduce(0, Integer::sum);
    }

    public boolean hasVulnerabilities() { return !vulnerabilitiesBySeverity.isEmpty(); }

    @Override
    public String toString() {

        String output = version;

        int count = getVulnerabilityCount();

        if (count == 0) {
            output = output + " (no vulnerabilities found)";
        } else {
            StringJoiner severityDetails = new StringJoiner(", ");
            for (Severity severity : Severity.values()) {
                int severityCount = vulnerabilitiesBySeverity.getOrDefault(severity, 0);
                if (severityCount > 0) {
                    severityDetails.add(severityCount + " " + severity);
                }
            }
            output = output + " (" + count + " known vulnerabilit" + (count == 1 ? "y" : "ies") + " remaining: " + severityDetails + ")";
        }

        return output;

    }

}
