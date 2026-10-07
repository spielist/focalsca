package com.focalsca.report;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

import java.util.List;

@JsonPropertyOrder({"$schema", "version", "runs"})
@JsonInclude(JsonInclude.Include.NON_NULL)
public record SarifLog(
        @JsonProperty("$schema") String schema,
        String version,
        List<Run> runs
) {
    public static SarifLog of(List<Run> runs) {
        return new SarifLog(
                "https://json.schemastore.org/sarif-2.1.0.json", "2.1.0", runs);
    }

    public record Run(Tool tool, List<Result> results) {
    }

    public record Tool(Driver driver) {
    }

    public record Driver(String name, String version, List<Rule> rules) {
    }

    public record Rule(String id, Message shortDescription) {
    }

    public record Result(String ruleId, String level, Message message,
                         List<Location> locations) {
    }

    public record Message(String text) {
    }

    public record Location(PhysicalLocation physicalLocation) {
    }

    public record PhysicalLocation(ArtifactLocation artifactLocation, Region region) {
    }

    public record ArtifactLocation(String uri) {
    }

    public record Region(Integer startLine) {
    }

}
