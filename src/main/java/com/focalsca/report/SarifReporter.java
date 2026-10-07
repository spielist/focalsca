package com.focalsca.report;

import java.io.File;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.focalsca.model.*;
import com.focalsca.report.SarifLog.*;

public class SarifReporter implements IReporter {

    @Override
    public void report(List<DependencyScanResult> scanResults, File reportFile) throws Exception {

        List<Result> results = scanResults.stream().flatMap(scanResult ->
            scanResult.getVulnerabilities().stream().map(vulnerability ->
                    toResult(scanResult.getDependency(), vulnerability))).toList();

        var log = SarifLog.of(List.of(
                new Run(new Tool(new Driver("Focal SCA", "0.1.0", List.of())), results)));

        ObjectMapper mapper = new ObjectMapper()
                .enable(SerializationFeature.INDENT_OUTPUT)
                .setSerializationInclusion(JsonInclude.Include.NON_NULL);
        mapper.writeValue(reportFile, log);

    }

    private static Result toResult(Dependency dep, Vulnerability vulnerability) {
        String description = dep.toCoordinate();
        if(!dep.isDirect() && dep.getParent() != null) {
            description += " (via " + dep.getParent().toCoordinate() + ")";
        }
        description += " - " + vulnerability.getSummary();
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
