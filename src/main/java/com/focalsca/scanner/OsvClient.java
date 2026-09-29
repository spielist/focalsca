package com.focalsca.scanner;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.focalsca.model.Dependency;
import com.focalsca.model.Severity;
import com.focalsca.model.Vulnerability;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class OsvClient {

    private static final String OSV_QUERY_URL = "https://api.osv.dev/v1/query";

    private final HttpClient httpClient = HttpClient.newHttpClient();
    private final ObjectMapper objectMapper = new ObjectMapper();

    public List<Vulnerability> query(Dependency dependency) {

        try {
            String requestBody = objectMapper.writeValueAsString(new OsvQueryRequest(dependency));

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(OSV_QUERY_URL))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                System.err.println("OSV.dev returned status " + response.statusCode()
                        + " for " + dependency.toCoordinate());
                return Collections.emptyList();
            }

            return parseResponse(response.body(), dependency);

        } catch (Exception e) {
            System.err.println("Error querying OSV.dev for " + dependency.toCoordinate() + ": " + e.getMessage());
            return Collections.emptyList();
        }
    }

    private List<Vulnerability> parseResponse(String responseBody, Dependency dependency) throws Exception {

        List<Vulnerability> results = new ArrayList<>();
        JsonNode root = objectMapper.readTree(responseBody);
        JsonNode vulns = root.path("vulns");

        if (vulns.isMissingNode() || !vulns.isArray()) {
            return Collections.emptyList();
        }

        for (JsonNode vuln : vulns) {

            String id = vuln.path("id").asText();
            String summary = vuln.path("summary").asText(null);
            String details = vuln.path("details").asText(null);

            List<String> aliases = new ArrayList<>();
            for (JsonNode alias : vuln.path("aliases")) {
                aliases.add(alias.asText());
            }

            Severity severity = parseSeverity(vuln);
            List<String> fixedVersions = parseFixedVersions(vuln);

            results.add(new Vulnerability(id, aliases, summary, details, severity, fixedVersions, dependency));
        }

        return results;
    }

    private Severity parseSeverity(JsonNode vuln) {
        // Try CVSS score from severity array first
        JsonNode severityArray = vuln.path("severity");
        for (JsonNode s : severityArray) {
            String score = s.path("score").asText("");
            double cvssScore = parseCvssScore(score);
            if (cvssScore >= 9.0) return Severity.CRITICAL;
            if (cvssScore >= 7.0) return Severity.HIGH;
            if (cvssScore >= 4.0) return Severity.MEDIUM;
            if (cvssScore > 0.0)  return Severity.LOW;
        }
        // Fall back to database_specific severity if present
        JsonNode dbSpecific = vuln.path("database_specific");
        String sev = dbSpecific.path("severity").asText("");
        return switch (sev.toUpperCase()) {
            case "CRITICAL" -> Severity.CRITICAL;
            case "HIGH"     -> Severity.HIGH;
            case "MEDIUM", "MODERATE" -> Severity.MEDIUM;
            case "LOW"      -> Severity.LOW;
            default         -> Severity.MEDIUM; // conservative default
        };
    }

    private double parseCvssScore(String cvssVector) {
        // CVSS vectors don't embed the numeric score directly —
        // OSV sometimes puts the numeric score in the score field directly
        try {
            return Double.parseDouble(cvssVector);
        } catch (NumberFormatException e) {
            return 0.0;
        }
    }

    private List<String> parseFixedVersions(JsonNode vuln) {
        List<String> fixedVersions = new ArrayList<>();
        for (JsonNode affected : vuln.path("affected")) {
            for (JsonNode range : affected.path("ranges")) {
                if ("ECOSYSTEM".equals(range.path("type").asText())) {
                    for (JsonNode event : range.path("events")) {
                        if (event.has("fixed")) {
                            fixedVersions.add(event.path("fixed").asText());
                        }
                    }
                }
            }
        }
        return fixedVersions;
    }

    // Inner class for the OSV request body
    private static class OsvQueryRequest {

        @JsonProperty("package")
        public final OsvPackage pkg;
        public final String version;

        OsvQueryRequest(Dependency dependency) {
            this.pkg = new OsvPackage(dependency.getGroupId() + ":" + dependency.getArtifactId(), "Maven");
            this.version = dependency.getVersion();
        }
    }

    private static class OsvPackage {
        public final String name;
        public final String ecosystem;

        OsvPackage(String name, String ecosystem) {
            this.name = name;
            this.ecosystem = ecosystem;
        }
    }

}