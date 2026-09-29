package com.focalsca.report;

import com.focalsca.model.Dependency;
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

import com.focalsca.scanner.FixVersionResult;
import com.focalsca.util.VersionUtils;
import org.apache.maven.artifact.versioning.ComparableVersion;

public class ConsoleTreeReporter {

    private static final String BRANCH     = "├── ";
    private static final String LAST       = "└── ";
    private static final String VERTICAL   = "│   ";
    private static final String INDENT     = "    ";

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
                .collect(Collectors.toList());

        if (vulnerableRoots.isEmpty()) {
            System.out.println("No vulnerabilities found.");
            System.out.println("===========================================");
            return;
        }

        System.out.println("VULNERABLE DEPENDENCIES (" + vulnerableRoots.size() + " top-level artifacts affected):");

        for (String rootCoordinate : vulnerableRoots) {
            List<DependencyScanResult> subtree = byRoot.get(rootCoordinate);

            // Find the root result
            DependencyScanResult rootResult = subtree.stream()
                    .filter(r -> r.getDependency().isDirect())
                    .findFirst()
                    .orElse(subtree.get(0));

            // Collect vulnerable transitives — deduplicated by coordinate
            Set<String> seen = new LinkedHashSet<>();
            List<DependencyScanResult> vulnerableTransitives = subtree.stream()
                    .filter(r -> !r.getDependency().isDirect())
                    .filter(DependencyScanResult::hasVulnerabilities)
                    .filter(r -> seen.add(r.getDependency().toCoordinate()))
                    .collect(Collectors.toList());

            // Determine tree structure
            List<Vulnerability> directVulns = sorted(rootResult.getVulnerabilities());
            boolean hasDirectVulns = !directVulns.isEmpty();
            boolean hasTransitives = !vulnerableTransitives.isEmpty();

            System.out.println();
            System.out.println(rootCoordinate + "  [direct]");

            // Build the list of top-level branches under the root:
            // direct CVEs first (or "no direct vulnerabilities"), then transitive deps
            if (!hasDirectVulns && !hasTransitives) continue;

            if (!hasDirectVulns) {
                // Only show "no direct vulnerabilities" if there are transitives to follow
                String connector = BRANCH; // transitives will follow
                System.out.println(connector + "No direct vulnerabilities.");
            } else {
                for (int i = 0; i < directVulns.size(); i++) {
                    boolean lastVuln = (i == directVulns.size() - 1) && !hasTransitives;
                    String connector = lastVuln ? LAST : BRANCH;
                    String continuation = lastVuln ? INDENT : VERTICAL;
                    printVulnerability(directVulns.get(i), connector, continuation);
                }
            }

            // Transitive vulnerable dependencies
            for (int i = 0; i < vulnerableTransitives.size(); i++) {
                DependencyScanResult transitive = vulnerableTransitives.get(i);
                boolean lastTransitive = (i == vulnerableTransitives.size() - 1);
                String transitiveConnector = lastTransitive ? LAST : BRANCH;
                String transitiveContinuation = lastTransitive ? INDENT : VERTICAL;

                System.out.println(transitiveConnector
                        + transitive.getDependency().toCoordinate() + "  [transitive]");

                List<Vulnerability> transitiveVulns = sorted(transitive.getVulnerabilities());
                for (int j = 0; j < transitiveVulns.size(); j++) {
                    boolean lastVuln = (j == transitiveVulns.size() - 1);
                    String vulnConnector = transitiveContinuation + (lastVuln ? LAST : BRANCH);
                    String vulnContinuation = transitiveContinuation + (lastVuln ? INDENT : VERTICAL);
                    printVulnerability(transitiveVulns.get(j), vulnConnector, vulnContinuation);
                }
            }

            FixVersionResult sameMajorFix = rootResult.getSameMajorFix();
            FixVersionResult crossMajorFix = rootResult.getCrossMajorFix();

            if (sameMajorFix != null) {
                System.out.println("Best major fix version available: " + sameMajorFix);
            }
            if (crossMajorFix != null) {
                boolean addsClarification = sameMajorFix == null ||
                        VersionUtils.majorVersion(crossMajorFix.getVersion()) > VersionUtils.majorVersion(sameMajorFix.getVersion());
                if (addsClarification) {
                    System.out.println("Best cross-major fix available: " + crossMajorFix);
                }
            }

        }

        // Severity summary
        Set<String> counted = new LinkedHashSet<>();
        List<Vulnerability> allVulns = results.stream()
                .filter(r -> counted.add(r.getDependency().toCoordinate()))
                .flatMap(r -> r.getVulnerabilities().stream())
                .collect(Collectors.toList());

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
        System.out.println("Rerun FocalSCA after upgrading to verify a clean scan.");
        System.out.println();
    }

    private void printVulnerability(Vulnerability v, String connector, String continuation) {
        String severityLabel = String.format("[%-8s]", v.getSeverity());
        String summary = v.getSummary() != null ? " — " + v.getSummary() : "";
        String reachability = v.getReachabilityResult().isAnalyzed()
                ? " [" + v.getReachabilityResult().getStatus() + "]"
                : "";
        System.out.println(connector + severityLabel + " " + v.getCveId() + summary + reachability);

        if (v.getReachabilityResult().isReachable()) {
            v.getReachabilityResult().getReachableVia()
                    .forEach(ep -> System.out.println(continuation + "Via: " + ep));
        }
    }

    private List<Vulnerability> sorted(List<Vulnerability> vulns) {
        return vulns.stream()
                .sorted(Comparator.comparing(Vulnerability::getSeverity))
                .collect(Collectors.toList());
    }

    private int majorVersion(String version) {
        try {
            return Integer.parseInt(version.split("[.\\-]")[0]);
        } catch (NumberFormatException e) {
            return -1; // unparseable — exclude it
        }
    }

}