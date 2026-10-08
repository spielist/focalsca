package com.focalsca.fix;

import com.focalsca.model.Dependency;
import com.focalsca.model.DependencyFix;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

public class BuildFileRewriter {

    public void rewrite(Path projectRoot, Path tempPath,
                        List<DependencyFix> fixes) throws Exception {

        Path outDir = Files.createTempDirectory(tempPath, "fixed");

        // group the fixes by build file
        Map<String, List<DependencyFix>> fixesByFile = new LinkedHashMap<>();
        fixes.forEach(fix -> {
            if (fix.getOriginal().isDirect()) {
                fixesByFile.computeIfAbsent(fix.getOriginal().getFile(),
                        k -> new ArrayList<>()).add(fix);
            }
        });

        // loop through files, replacing dependencies with candidate fix versions
        for(String fileName : fixesByFile.keySet()) {
            int fixesApplied = 0;
            List<String> lines = new ArrayList<>(Files.readAllLines(projectRoot.resolve(fileName)));
            List<DependencyFix> fileFixes = fixesByFile.get(fileName);
            for(DependencyFix fix : fileFixes) {
                Integer index = fix.getOriginal().getLine();
                if(index != null) {
                    String patched = patchLine(lines.get(index - 1), fix.getOriginal(), fix.getNewVersion());
                    if (patched != null) {
                        System.out.println(fix.getOriginal().toCoordinate() + " updated to " + fix.getNewVersion());
                        lines.set(index - 1, patched);
                        fixesApplied++;
                    } else {
                        System.out.println(fix.getOriginal().toCoordinate() + " not located in " + fileName);
                    }
                } else {
                    System.out.println(fix.getOriginal().toCoordinate() + ": no line number in " + fileName);
                }
            }
            if(fixesApplied > 0) {
                Path target = outDir.resolve(fileName).normalize();
                if (!target.startsWith(outDir)) {
                    throw new IOException("Refusing to write outside temp directory: " + target);
                }
                Files.createDirectories(target.getParent());
                Files.write(target, lines);
            }
        }

        return;

    }

    /** Returns the line with the version replaced, or null if the old version isn't on it. */
    private String patchLine(String line, Dependency original, String newVersion) {
        String oldVersion = original.getVersion();
        String stringForm = original.getArtifactId() + ":" + oldVersion;
        if (line.contains(stringForm)) {
            return line.replace(stringForm, original.getArtifactId() + ":" + newVersion);
        }
        if (line.contains(original.getArtifactId()) && line.contains(oldVersion)) {   // version: '1.2.3'
            int at = line.lastIndexOf(oldVersion);
            return line.substring(0, at) + newVersion + line.substring(at + oldVersion.length());
        }
        return null;
    }

}
