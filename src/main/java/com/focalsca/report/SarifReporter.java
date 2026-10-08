package com.focalsca.report;

import java.io.File;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.focalsca.model.*;
import com.focalsca.report.SarifLog.*;

public class SarifReporter implements IReporter {

    @Override
    public void report(List<DependencyScanResult> scanResults, File reportFile) throws Exception {

//        List<Result> results = scanResults.stream().flatMap(scanResult ->
//            scanResult.getVulnerabilities().stream().map(vulnerability ->
//                    toResult(scanResult.getDependency(), vulnerability))).toList();

        // de-duplicate results
        Set<String> seen = new HashSet<>();
        List<Result> results = scanResults.stream()
                .flatMap(scanResult -> scanResult.getVulnerabilities().stream()
                        .filter(vuln -> seen.add(resultKey(scanResult.getDependency(), vuln)))
                        .map(vuln -> toResult(scanResult.getDependency(), vuln)))
                .toList();

        var log = SarifLog.of(List.of(
                new Run(new Tool(new Driver("Focal SCA", "0.1.0", List.of())), results)));

        ObjectMapper mapper = new ObjectMapper()
                .enable(SerializationFeature.INDENT_OUTPUT)
                .setSerializationInclusion(JsonInclude.Include.NON_NULL);
        mapper.writeValue(reportFile, log);

    }

    private static String resultKey(Dependency dep, Vulnerability vuln) {
        return String.join("|", vuln.getCveId(), dep.toCoordinate(),
                dep.getRootDependency().toCoordinate(),
                String.valueOf(dep.getFile()), String.valueOf(dep.getLine()));
    }

    private static Result toResult(Dependency dep, Vulnerability vulnerability) {
        String description = dep.toCoordinate();
        if (!dep.isDirect()) {
            description += " (introduced through " + dep.getRootDependency().toCoordinate() + ")";
        }
        if (vulnerability.getSummary() != null) {
            description += " - " + vulnerability.getSummary();
        }
        var physical = new PhysicalLocation(
                new ArtifactLocation(dep.getFile()),
                dep.getLine() != null ? new Region(dep.getLine()) : null);
        return new Result(
                vulnerability.getCveId(),
                toLevel(vulnerability.getSeverity()),
                new Message(description),
                List.of(new Location(physical)));
    }

    private static String toLevel(Severity severity) {
        return switch (severity) {
            case CRITICAL, HIGH -> "error";
            case MEDIUM -> "warning";
            default -> "note";
        };
    }

}
