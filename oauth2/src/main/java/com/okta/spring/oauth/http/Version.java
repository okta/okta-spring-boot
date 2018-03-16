/*
 * Copyright 2014 Stormpath, Inc.
 * Modifications Copyright 2018 Okta, Inc.
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
package com.okta.spring.oauth.http;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

/**
 * @since 0.4.0
 */
class Version {

    private static final String VERSION_FILE = "/com/okta/spring/version.properties";
    private static final String CLIENT_VERSION = lookupClientVersion(VERSION_FILE);

    private Version() {}

    public static String getClientVersion() {
        return CLIENT_VERSION;
    }

    public static String getClientVersion(String versionFile) {
        return lookupClientVersion(versionFile);
    }

    private static String lookupClientVersion(String versionFile) {
        Class clazz = Version.class;
        InputStream inputStream = null;
        BufferedReader reader = null;
        try {
            inputStream = clazz.getResourceAsStream(versionFile);
            reader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8));
            String line;
            do {
                line = reader.readLine();
            } while (line != null && (line.startsWith("#") || line.isEmpty()));
            return line;
        } catch (IOException e) {
            throw new RuntimeException("Unable to obtain version from [" + versionFile + "].", e);
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    throw new RuntimeException("Exception while trying to close file [" + versionFile + "].", e);
                }
            }
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (IOException e) {
                    throw new RuntimeException("Exception while trying to close file [" + versionFile + "].", e);
                }
            }
        }
    }
}