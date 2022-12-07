/*
 * Copyright 2022-Present Okta, Inc.
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
package com.okta.spring.boot.oauth;

public abstract class OktaOAuth2CustomParam {

    /**
     * Authentication Context Reference
     */
    public static final String ACR_VALUES = "acr_values";

    /**
     * Support enrollment of a factor during an /authorize call by adding the following this parameter value.
     */
    public static final String PROMPT = "prompt";

    /**
     * space-delimited, case-sensitive string that represents a list of authenticator method references.
     */
    public static final String ENROLL_AMR_VALUES = "enroll_amr_values";

    /**
     * Allowable elapsed time, in seconds, since the last time the end user was actively authenticated by Okta.
     */
    public static final String MAX_AGE = "max_age";

}
