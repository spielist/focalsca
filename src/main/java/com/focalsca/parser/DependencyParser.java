package com.focalsca.parser;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.focalsca.model.Dependency;

import java.io.IOException;
import java.nio.file.Path;
import java.util.*;

public class DependencyParser {

    private final ObjectMapper objectMapper = new ObjectMapper();

    public List<Dependency> parse(Path jsonFilePath) throws IOException {
        List<RawDependency> raw = objectMapper.readValue(jsonFilePath.toFile(), new TypeReference<>() {});
        return raw.stream().map(this::toDependency).toList();
    }

    private Dependency toDependency(RawDependency raw) {
        Dependency dependency = Dependency.fromCoordinate(raw.id, raw.file, raw.line);
        for (RawDependency rawChild : raw.children) {
            dependency.addChild(toDependency(rawChild));
        }
        return dependency;
    }

}
