package com.focalsca.cli;

import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.List;
import java.util.concurrent.Callable;

import com.focalsca.model.*;
import com.focalsca.report.ConsoleTreeReporter;
import com.focalsca.scanner.DependencyScanner;
import com.focalsca.parser.DependencyParser;
import com.focalsca.report.ConsoleReporter;
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

    @Option(names = "--project", required = true, description = "Path to Gradle project",
            defaultValue = "C:\\Users\\moong\\Projects\\cardgen")
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

    @Override
    public Integer call() throws Exception {

        Path initScript = Files.createTempFile("init", ".gradle");
        try (InputStream inputStream = Main.class.getResourceAsStream("/init-script.gradle")) {
            Files.copy(inputStream, initScript, StandardCopyOption.REPLACE_EXISTING);
        }

        // TODO: convert to temporary file
        File outputFile = new File("build/target-dependencies.json");

        try (ProjectConnection connection = GradleConnector.newConnector()
                .forProjectDirectory(new File(projectPath.toAbsolutePath().toString()))
                .connect()) {
            connection.newBuild().forTasks("listDependencies")
                    .withArguments("-I", initScript.toAbsolutePath().toString(),
                            "-PscanOutputPath=" + outputFile.toPath().toAbsolutePath())
                    .run();
        }

        DependencyParser parser = new DependencyParser();
        List<Dependency> dependencyList = parser.parse(outputFile);

        DependencyScanner scanner = new DependencyScanner();
        List<DependencyScanResult> scannerResults = scanner.scan(dependencyList, upgradePolicy);

        ConsoleTreeReporter reporter = new ConsoleTreeReporter();
        reporter.report(scannerResults);

//        Files.deleteIfExists(outputFile.toPath());
        Files.deleteIfExists(initScript);

        if (warnOnly) return 0;

        boolean failingVulnFound = scannerResults.stream()
                .flatMap(r -> r.getVulnerabilities().stream())
                .anyMatch(v -> v.getSeverity().compareTo(failOn) <= 0);

        return failingVulnFound ? 1 : 0;

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
