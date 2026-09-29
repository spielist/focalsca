package com.focalsca.scanner;

import java.util.*;

import com.focalsca.model.Dependency;
import com.focalsca.model.DependencyScanResult;
import com.focalsca.model.UpgradePolicy;
import com.focalsca.model.Vulnerability;
import com.focalsca.util.VersionUtils;
import org.apache.maven.artifact.versioning.ComparableVersion;

public class DependencyScanner {

    public List<DependencyScanResult> scan(List<Dependency> dependencyList, UpgradePolicy upgradePolicy) {

        HashMap<String, DependencyScanResult> uniqueScanResults = new HashMap<>();
        OsvClient osv = new OsvClient();

        List<DependencyScanResult> list = dependencyList.stream().map(dependency -> {
            DependencyScanResult prevResult = uniqueScanResults.get(dependency.toCoordinate());
            if (prevResult == null) {
                List<Vulnerability> vulns = osv.query(dependency);
                DependencyScanResult result = new DependencyScanResult(dependency, vulns);
                uniqueScanResults.put(dependency.toCoordinate(), result);
                return result;
            } else {
                return new DependencyScanResult(dependency, prevResult.getVulnerabilities());
            }
        }).toList();

        list.forEach(result -> {
            if (result.getDependency().isDirect()) {
                DependencyScanResult cached = uniqueScanResults.get(result.getDependency().toCoordinate());
                if (cached != null && cached.getSameMajorFix() == null) {
                    cached.setSameMajorFix(getBestFixVersion(osv, cached, 0,
                            new HashSet<>(), UpgradePolicy.SAME_MAJOR));
                    cached.setCrossMajorFix(getBestFixVersion(osv, cached, 0,
                            new HashSet<>(), UpgradePolicy.ANY));
                }
                result.setSameMajorFix(cached.getSameMajorFix());
                result.setCrossMajorFix(cached.getCrossMajorFix());
            }
        });

        return list;

    }

    public FixVersionResult getBestFixVersion(OsvClient osv, DependencyScanResult result,
                                              int depth, Set<String> visited,
                                              UpgradePolicy upgradePolicy) {

//        System.out.println("getBestFixVersion called for: " + result.getDependency().toCoordinate()
//                + " depth=" + depth + " vulns=" + result.getVulnerabilities().size());

        int installedMajor = VersionUtils.majorVersion(result.getDependency().getVersion());

        Optional<String> fixVersion = result.getVulnerabilities().stream()
                .flatMap(v -> v.getFixedVersions().stream())
                .filter(v -> v != null)
                .filter(v -> upgradePolicy == UpgradePolicy.ANY || VersionUtils.majorVersion(v) == installedMajor)
                .max(Comparator.comparing(ComparableVersion::new));

//        System.out.println("fixVersion result: " + fixVersion + " installedMajor=" + installedMajor
//                + " upgradePolicy=" + upgradePolicy);

        if (fixVersion.isEmpty()) {
            return null;
        }

        String candidate = fixVersion.get();

        if (depth >= 5 || !visited.add(candidate)) {
            // At max depth — return what we have with current vuln count
            return new FixVersionResult(candidate, result.getVulnerabilities());
        }

        Dependency fixCandidate = Dependency.fromCoordinate(
                result.getDependency().getGroupId() + ":" +
                        result.getDependency().getArtifactId() + ":" +
                        candidate
        );

        List<Vulnerability> fixVulns = osv.query(fixCandidate);

        if (fixVulns.isEmpty()) {
            return new FixVersionResult(candidate, Collections.emptyList()); // clean
        }

        // Fix version has its own vulnerabilities — recurse to find better
        FixVersionResult betterFix = getBestFixVersion(osv, new DependencyScanResult(fixCandidate, fixVulns),
                depth + 1, visited, upgradePolicy);

        // If no better fix found, return the candidate we have with its vuln count
        return betterFix != null ? betterFix : new FixVersionResult(candidate, fixVulns);
    }
}
