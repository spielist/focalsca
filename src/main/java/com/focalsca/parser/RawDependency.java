package com.focalsca.parser;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public class RawDependency {

    public String id;
    public String parent;
    public int level;

}
