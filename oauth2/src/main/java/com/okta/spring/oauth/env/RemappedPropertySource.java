/*
 * Copyright 2017 Okta, Inc.
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
package com.okta.spring.oauth.env;

import org.springframework.core.env.EnumerablePropertySource;
import org.springframework.core.env.Environment;
import org.springframework.core.env.PropertySource;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * A {@link PropertySource} that supports aliasing/renaming of keys.  For alias the key {@code foo} to the key
 * {@code {bar}} whenever either of the values are looked up they will return the same value. This differs from setting
 * {@code foo=${bar}}, in that if the value of {@code bar} is {@code null}, {@code null} is returned,
 * if {@code ${bar}} was used, an exception would be thrown due to the unresolvable property {@code bar}.
 * 
 * @since 0.3.0
 */
public class RemappedPropertySource extends EnumerablePropertySource<String> {

    private final Map<String, String> aliasMap = new HashMap<>();
    private final Environment environment;

    public RemappedPropertySource(String name, Map<String, String> aliasMap, Environment environment) {
        super(name);
        this.aliasMap.putAll(aliasMap);
        this.environment = environment;
    }

    @Override
    public Object getProperty(String name) {

        String remappedKey = aliasMap.get(name);
        if (remappedKey != null) {
            return environment.getProperty(remappedKey);
        }

        return null;
    }

    @Override
    public String[] getPropertyNames() {
        return aliasMap.keySet().toArray(new String[0]);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        RemappedPropertySource that = (RemappedPropertySource) o;
        return Objects.equals(aliasMap, that.aliasMap) &&
                Objects.equals(environment, that.environment);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), aliasMap, environment);
    }
}