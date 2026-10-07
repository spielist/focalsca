package com.focalsca.cli;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.stream.Stream;

import com.focalsca.model.*;
import com.focalsca.report.ConsoleTreeReporter;
import com.focalsca.report.IReporter;
import com.focalsca.report.SarifReporter;
import com.focalsca.scanner.DependencyScanner;
import com.focalsca.parser.DependencyParser;
import com.focalsca.scanner.FixVersionResult;
import org.apache.commons.io.file.PathUtils;
import org.gradle.tooling.GradleConnector;
import org.gradle.tooling.ProjectConnection;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.ITypeConverter;

@Command
public class Main implements Callable<Integer> {

    public static void main(String[] args) {
        System.exit(new CommandLine(new Main()).execute(args));
    }

    @Option(names = "--project", required = true, description = "Path to Gradle project")
    Path projectPath;

    @Option(names = "--output-format", defaultValue = "console", converter = OutputFormatConverter.class)
    OutputFormat outputFormat;

    @Option(names = "--fail-on", defaultValue = "high", converter = SeverityConverter.class)
    Severity failOn;

    @Option(names = "--warn-only")
    boolean warnOnly;

    @Option(names = "--cache-dir")
    Path cacheDir;

    @Option(names = "--upgrade-policy", defaultValue = "SAME_MAJOR",
            converter = UpgradePolicyConverter.class,
            description = "Controls recommended upgrade versions: SAME_MAJOR (default) or ANY")
    UpgradePolicy upgradePolicy;

    @Option(names = "--verify-fixes",
            description = "Resolve each recommended fix version and scan its transitive dependencies (slower)")
    boolean verifyFixes;

    @Override
    public Integer call() throws Exception {

        Path tempPath = Paths.get("c:\\users\\moong\\Projects\\focalsca\\temp");

        Path initScript = Files.createTempFile(tempPath, "init", ".gradle");
        try (InputStream inputStream = Main.class.getResourceAsStream("/init-script.gradle")) {
            Files.copy(inputStream, initScript, StandardCopyOption.REPLACE_EXISTING);
        }

        Path outDir = Files.createTempDirectory(tempPath, "dependencies");
        try (ProjectConnection connection = GradleConnector.newConnector()
                .forProjectDirectory(new File(projectPath.toAbsolutePath().toString()))
                .connect()) {
            connection.newBuild().forTasks("listDependencies")
                    .withArguments("-I", initScript.toAbsolutePath().toString(),
                            "-PscanOutputPath=" + outDir.toAbsolutePath())
                    .run();
        }

        List<Dependency> dependencyList = runParser(outDir);
        List<DependencyScanResult> scannerResults = runScanner(dependencyList);
        runReporter(scannerResults, "results.sarif");

        if (verifyFixes && (upgradePolicy == UpgradePolicy.ANY || upgradePolicy == UpgradePolicy.SAME_MAJOR)) {
            Map<String, Dependency> fixCandidates = new HashMap<>();
            scannerResults.forEach(result -> {
                Dependency dependency = result.getDependency();
                if(dependency.isDirect() && result.hasVulnerabilities()) {
                    FixVersionResult fixVersion = switch(upgradePolicy) {
                        case ANY -> result.getCrossMajorFix();
                        case SAME_MAJOR -> result.getSameMajorFix();
                    };
                    if(fixVersion != null) {
                        String candidateVersion = String.join(":", dependency.getGroupId(), dependency.getArtifactId(),
                                upgradePolicy == UpgradePolicy.ANY ? result.getCrossMajorFix().getVersion() : result.getSameMajorFix().getVersion());
                        Dependency candidate = Dependency.fromCoordinate(candidateVersion, dependency.getFile(), dependency.getLine());
                        fixCandidates.put(candidateVersion, candidate);
                    }
                }
            });
            if(!fixCandidates.isEmpty()) {
                // second Gradle invocation: resolveCandidates
                Path candidateDir = Files.createTempDirectory(tempPath, "fixcandidates");
                try (ProjectConnection connection = GradleConnector.newConnector()
                        .forProjectDirectory(new File(projectPath.toAbsolutePath().toString()))
                        .connect()) {
                    connection.newBuild().forTasks("resolveCandidates")
                            .withArguments("-I", initScript.toAbsolutePath().toString(),
                                    "-PscanOutputPath=" + candidateDir.toAbsolutePath(),
                                    "-PfixCandidates=" + String.join(",", fixCandidates.keySet()))
                            .run();
                }
                List<Dependency> candidateDeps = runParser(candidateDir.toAbsolutePath());
                List<DependencyScanResult> candidateResults = runScanner(candidateDeps);
                runReporter(candidateResults, "fixcandidates.sarif");
            }
        }

        PathUtils.delete(initScript);

        if (warnOnly) return 0;

        boolean failingVulnFound = scannerResults.stream()
                .flatMap(r -> r.getVulnerabilities().stream())
                .anyMatch(v -> v.getSeverity().compareTo(failOn) <= 0);

        return failingVulnFound ? 1 : 0;

    }

    private List<Dependency> runParser(Path outDir) throws IOException {
        DependencyParser parser = new DependencyParser();
        List<Dependency> dependencyList = new ArrayList<>();
        try (Stream<Path> files = Files.list(outDir)) {
            List<Path> jsonFiles = files.filter(path -> path.toString().endsWith(".json")).toList();
            jsonFiles.forEach(path -> {
                try {
                    dependencyList.addAll(parser.parse(path));
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            });
        }
        PathUtils.delete(outDir);
        return dependencyList;
    }

    private List<DependencyScanResult> runScanner(List<Dependency> dependencyList) {
        return new DependencyScanner().scan(dependencyList, upgradePolicy);
    }

    private void runReporter(List<DependencyScanResult> scannerResults, String fileName) throws Exception {
        IReporter reporter = switch(outputFormat) {
            case CONSOLE -> new ConsoleTreeReporter();
            case SARIF -> new SarifReporter();
            default -> new SarifReporter();
        };
        reporter.report(scannerResults, new File(fileName));
    }

    static class OutputFormatConverter implements ITypeConverter<OutputFormat> {
        public OutputFormat convert(String value) {
            return OutputFormat.valueOf(value.toUpperCase());
        }
    }

    static class SeverityConverter implements ITypeConverter<Severity> {
        public Severity convert(String value) {
            return Severity.valueOf(value.toUpperCase());
        }
    }

    static class UpgradePolicyConverter implements ITypeConverter<UpgradePolicy> {
        public UpgradePolicy convert(String value) {
            return UpgradePolicy.valueOf(value.toUpperCase());
        }
    }

}
