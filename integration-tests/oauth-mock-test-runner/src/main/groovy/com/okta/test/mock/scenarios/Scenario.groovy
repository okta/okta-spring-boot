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
package com.okta.test.mock.scenarios

enum Scenario {

    CODE_FLOW_LOCAL_VALIDATION("code-flow-local-validation", new CodeLocalValidationScenarioDefinition()),
    CODE_FLOW_REMOTE_VALIDATION("code-flow-remote-validation", new CodeRemoteValidationScenarioDefinition()),
    IMPLICIT_FLOW_LOCAL_VALIDATION("implicit-flow-local-validation", new ImplicitLocalValidationScenarioDefinition()),
    IMPLICIT_FLOW_REMOTE_VALIDATION("implicit-flow-remote-validation", new ImplicitRemoteValidationScenarioDefinition())

    static Map<String, Scenario> LOOKUP_MAP = new HashMap<>()
    static {
        LOOKUP_MAP.put( CODE_FLOW_LOCAL_VALIDATION.id, CODE_FLOW_LOCAL_VALIDATION)
        LOOKUP_MAP.put( CODE_FLOW_REMOTE_VALIDATION.id, CODE_FLOW_REMOTE_VALIDATION)
        LOOKUP_MAP.put( IMPLICIT_FLOW_LOCAL_VALIDATION.id, IMPLICIT_FLOW_LOCAL_VALIDATION)
        LOOKUP_MAP.put( IMPLICIT_FLOW_REMOTE_VALIDATION.id, IMPLICIT_FLOW_REMOTE_VALIDATION)
    }

    private final String id
    private final ScenarioDefinition definition

    Scenario(String id, ScenarioDefinition definition) {
        this.id = id
        this.definition = definition
    }

    String getId() {
        return id
    }

    ScenarioDefinition getDefinition() {
        return definition
    }

    static Scenario fromId(String id) {
        return LOOKUP_MAP.get(id)
    }
}