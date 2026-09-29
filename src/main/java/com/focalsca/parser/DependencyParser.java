package com.focalsca.parser;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.focalsca.model.Dependency;

import java.io.File;
import java.io.IOException;
import java.util.*;

public class DependencyParser {

    private final ObjectMapper objectMapper = new ObjectMapper();

    public List<Dependency> parse(File jsonFile) throws IOException {

        List<Dependency> dependencies = new ArrayList<>();
        List<RawDependency> rawDependencies = objectMapper.readValue(jsonFile, new TypeReference<List<RawDependency>>() {});

        for (RawDependency rawDependency : rawDependencies) {
            if (rawDependency.level == 0) {
                Dependency dependency = Dependency.fromCoordinate(rawDependency.id);
                dependencies.add(dependency);
                addTransitives(rawDependencies, dependencies, dependency, 1);
            }
        }

        return dependencies;

    }

    private void addTransitives(List<RawDependency> rawDependencies, List<Dependency> dependencies, Dependency parent, int level) {
        for (RawDependency rawDependency : rawDependencies) {
            if (rawDependency.level == level && Objects.equals(rawDependency.parent, parent.toCoordinate())) {
                Dependency dependency = Dependency.fromCoordinate(rawDependency.id);
                dependency.setParent(parent);
                dependencies.add(dependency);
                addTransitives(rawDependencies, dependencies, dependency, level + 1);
            }
        }
    }

}
