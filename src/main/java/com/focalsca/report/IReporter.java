package com.focalsca.report;

import java.io.File;
import java.util.List;
import com.focalsca.model.DependencyScanResult;

public interface IReporter {

    void report(List<DependencyScanResult> results, File reportFile) throws Exception;

}
