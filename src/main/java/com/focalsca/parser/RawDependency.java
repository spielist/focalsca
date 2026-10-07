package com.focalsca.parser;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.ArrayList;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public class RawDependency {

    public String id;
    public String file;
    public Integer line;
    public List<RawDependency> children = new ArrayList<>();

}
