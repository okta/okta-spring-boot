package com.okta.spring.boot.oauth.http;

import java.io.IOException;
import java.net.URL;
import java.util.Properties;
import java.util.stream.Collectors;

import static java.util.Collections.list;

/**
 * Future method to load version metadata, aggregate data from META-INF/okta/version.properties files
 */
public class VersionUtil {

    private static final String VERSION_FILE_LOCATION = "META-INF/okta/version.properties";

    public static String userAgentsFromVersionMetadata() throws IOException {
        return list(VersionUtil.class.getClassLoader().getResources(VERSION_FILE_LOCATION)).stream()
            .map(VersionUtil::loadProps)
            .map(properties -> properties.entrySet().stream()
                    .map(entry -> entry.getKey() +  "/" + entry.getValue())
                    .collect(Collectors.joining(" ")))
            .collect(Collectors.joining(" "));
    }

    private static Properties loadProps(URL resourceUrl) {
        try {
            Properties props = new Properties();
            props.load(resourceUrl.openStream());
            return props;
        } catch (IOException e) {
            throw new IllegalStateException("Failed to open resource "+ resourceUrl, e);
        }
    }
}
