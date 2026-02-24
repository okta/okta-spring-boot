/*
 * Copyright 2024-Present Okta, Inc.
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
package com.okta.spring.boot.oauth.enterprise;

/**
 * Represents an error that occurred during Enterprise Managed Authorization (SEP-990) operations,
 * including token exchange (RFC 8693) and JWT bearer grant (RFC 7523) failures.
 *
 * <p>When the server returns an OAuth 2.0 error response (RFC 6749 §5.2), the
 * {@link #getErrorCode()}, {@link #getErrorDescription()}, and {@link #getErrorUri()} fields
 * are populated from the response.</p>
 */
public class EnterpriseAuthException extends RuntimeException {

    private final String errorCode;
    private final String errorDescription;
    private final String errorUri;

    /**
     * Creates an instance with a plain message.
     *
     * @param message the error message
     */
    public EnterpriseAuthException(String message) {
        super(message);
        this.errorCode = null;
        this.errorDescription = null;
        this.errorUri = null;
    }

    /**
     * Creates an instance with a message and cause.
     *
     * @param message the error message
     * @param cause   the underlying cause
     */
    public EnterpriseAuthException(String message, Throwable cause) {
        super(message, cause);
        this.errorCode = null;
        this.errorDescription = null;
        this.errorUri = null;
    }

    /**
     * Creates an instance with OAuth error fields from an error response.
     *
     * @param message          human-readable summary of the failure
     * @param errorCode        the OAuth {@code error} code (e.g. {@code "invalid_grant"})
     * @param errorDescription the OAuth {@code error_description}
     * @param errorUri         the OAuth {@code error_uri}
     */
    public EnterpriseAuthException(String message, String errorCode, String errorDescription, String errorUri) {
        super(formatMessage(message, errorCode, errorDescription));
        this.errorCode = errorCode;
        this.errorDescription = errorDescription;
        this.errorUri = errorUri;
    }

    /**
     * Returns the OAuth error code, if available (e.g. {@code "invalid_request"},
     * {@code "invalid_grant"}).
     *
     * @return the OAuth error code, or {@code null}
     */
    public String getErrorCode() {
        return errorCode;
    }

    /**
     * Returns the human-readable error description from the OAuth error response.
     *
     * @return the error description, or {@code null}
     */
    public String getErrorDescription() {
        return errorDescription;
    }

    /**
     * Returns the URI of a human-readable web page with further error details.
     *
     * @return the error URI, or {@code null}
     */
    public String getErrorUri() {
        return errorUri;
    }

    private static String formatMessage(String message, String errorCode, String errorDescription) {
        if (errorCode != null && !errorCode.isEmpty()) {
            message = message + " Error: " + errorCode;
            if (errorDescription != null && !errorDescription.isEmpty()) {
                message = message + " (" + errorDescription + ")";
            }
        }
        return message;
    }
}
