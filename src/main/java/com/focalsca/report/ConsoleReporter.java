package com.focalsca.report;

import com.focalsca.model.DependencyScanResult;
import com.focalsca.model.Severity;
import com.focalsca.model.Vulnerability;

import java.util.Comparator;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class ConsoleReporter {

    public void report(List<DependencyScanResult> results) {

        long totalScanned = results.size();
        long directCount = results.stream().filter(r -> r.getDependency().isDirect()).count();
        long transitiveCount = totalScanned - directCount;

        System.out.println();
        System.out.println("FocalSCA Results — " + totalScanned + " dependencies scanned"
                + " (" + directCount + " direct, " + transitiveCount + " transitive)");
        System.out.println("===========================================");

        // Group all scan results by their root dependency coordinate
        Map<String, List<DependencyScanResult>> byRoot = results.stream()
                .collect(Collectors.groupingBy(
                        r -> r.getDependency().getRootDependency().toCoordinate(),
                        LinkedHashMap::new,
                        Collectors.toList()
                ));

        // Find root coordinates that have at least one vulnerability anywhere in their subtree
        List<String> vulnerableRoots = byRoot.entrySet().stream()
                .filter(e -> e.getValue().stream().anyMatch(DependencyScanResult::hasVulnerabilities))
                .map(Map.Entry::getKey)
                .toList();

        if (vulnerableRoots.isEmpty()) {
            System.out.println("No vulnerabilities found.");
            System.out.println("===========================================");
            return;
        }

        System.out.println("VULNERABLE DEPENDENCIES (" + vulnerableRoots.size() + " top-level artifacts affected):");

        for (String rootCoordinate : vulnerableRoots) {
            List<DependencyScanResult> subtree = byRoot.get(rootCoordinate);

            // The root result itself
            DependencyScanResult rootResult = subtree.stream()
                    .filter(r -> r.getDependency().isDirect())
                    .findFirst()
                    .orElse(subtree.get(0));

            System.out.println();
            System.out.println(rootCoordinate + "  [direct]");

            // Direct CVEs on the root artifact
            if (rootResult.hasVulnerabilities()) {
                for (Vulnerability v : sorted(rootResult.getVulnerabilities())) {
                    System.out.println(formatVulnerability(v, "  "));
                }
            } else {
                System.out.println("  No direct vulnerabilities.");
            }

            // Vulnerable transitive dependencies — deduplicated by coordinate
            Set<String> seen = new LinkedHashSet<>();
            List<DependencyScanResult> vulnerableTransitives = subtree.stream()
                    .filter(r -> !r.getDependency().isDirect())
                    .filter(DependencyScanResult::hasVulnerabilities)
                    .filter(r -> seen.add(r.getDependency().toCoordinate()))
                    .toList();

            if (!vulnerableTransitives.isEmpty()) {
                System.out.println();
                System.out.println("  Vulnerable transitive dependencies:");
                for (DependencyScanResult transitive : vulnerableTransitives) {
                    System.out.println("  " + transitive.getDependency().toCoordinate());
                    for (Vulnerability v : sorted(transitive.getVulnerabilities())) {
                        System.out.println(formatVulnerability(v, "    "));
                    }
                }
            }
        }

        // Severity summary — count across all unique vulnerable coordinates
        Set<String> counted = new LinkedHashSet<>();
        List<Vulnerability> allVulns = results.stream()
                .filter(r -> counted.add(r.getDependency().toCoordinate()))
                .flatMap(r -> r.getVulnerabilities().stream())
                .toList();

        Map<Severity, Long> countsBySeverity = new EnumMap<>(Severity.class);
        for (Severity s : Severity.values()) {
            long count = allVulns.stream().filter(v -> v.getSeverity() == s).count();
            if (count > 0) countsBySeverity.put(s, count);
        }

        String severitySummary = countsBySeverity.entrySet().stream()
                .map(e -> e.getValue() + " " + e.getKey())
                .collect(Collectors.joining(", "));

        System.out.println();
        System.out.println("===========================================");
        System.out.println(allVulns.size() + " vulnerabilit" + (allVulns.size() == 1 ? "y" : "ies") +
                " across " + vulnerableRoots.size() + " top-level artifact" +
                (vulnerableRoots.size() == 1 ? "" : "s") +
                " (" + severitySummary + ")");
        System.out.println();
    }

    private String formatVulnerability(Vulnerability v, String indent) {
        String severityLabel = String.format("[%-8s]", v.getSeverity());
        String summary = v.getSummary() != null ? " — " + v.getSummary() : "";
        String reachability = v.getReachabilityResult().isAnalyzed()
                ? " [" + v.getReachabilityResult().getStatus() + "]"
                : "";
        StringBuilder sb = new StringBuilder();
        sb.append(indent).append(severityLabel).append(" ").append(v.getCveId())
                .append(summary).append(reachability);
        if (v.getReachabilityResult().isReachable()) {
            v.getReachabilityResult().getReachableVia()
                    .forEach(ep -> sb.append("\n").append(indent).append("  Via: ").append(ep));
        }
        return sb.toString();
    }

    private List<Vulnerability> sorted(List<Vulnerability> vulns) {
        return vulns.stream()
                .sorted(Comparator.comparing(Vulnerability::getSeverity))
                .collect(Collectors.toList());
    }

}
