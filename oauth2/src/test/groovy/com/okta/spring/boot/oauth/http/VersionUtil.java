/*
 * Copyright 2018-Present Okta, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
