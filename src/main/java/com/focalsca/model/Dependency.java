package com.focalsca.model;

import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

@Getter
public class Dependency {

    private final String groupId;
    private final String artifactId;
    private final String version;
    private final String file;
    private final Integer line;
    private Dependency parent;
    private final List<Dependency> children = new ArrayList<>();

    @Setter
    private String bestFixVersion;

    private Dependency(String groupId, String artifactId, String version, String file, Integer line) {
        this.groupId = groupId;
        this.artifactId = artifactId;
        this.version = version;
        this.file = file;
        this.line = line;
        this.parent = null;
    }

    public static Dependency fromCoordinate(String coordinate, String file, Integer line) {
        String[] parts = coordinate.split(":");
        if (parts.length != 3) {
            throw new IllegalArgumentException("Invalid dependency coordinate: " + coordinate);
        }
        return new Dependency(parts[0], parts[1], parts[2], file, line);
    }

    public boolean isDirect() { return this.parent == null; }

    public Dependency getRootDependency() {
        Dependency current = this;
        while (current.parent != null) {
            current = current.parent;
        }
        return current;
    }

    public String toCoordinate() {
        return groupId + ":" + artifactId + ":" + version;
    }

    public String toPurl() {
        return "pkg:maven/" + groupId + "/" + artifactId + "@" + version;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Dependency)) return false;
        Dependency that = (Dependency) o;
        return Objects.equals(groupId, that.groupId) &&
                Objects.equals(artifactId, that.artifactId) &&
                Objects.equals(version, that.version);
    }

    @Override
    public int hashCode() {
        return Objects.hash(groupId, artifactId, version);
    }

    @Override
    public String toString() {
        return toCoordinate();
    }

    public void addChild(Dependency dependency) {
        dependency.parent = this;
        children.add(dependency);
    }
}
