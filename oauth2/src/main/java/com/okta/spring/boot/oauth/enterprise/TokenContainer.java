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

import java.time.Instant;

/**
 * Holds the result of a successful JWT Bearer Grant (RFC 7523) token exchange.
 *
 * <p>The {@link #isExpired()} method returns {@code true} when the access token has
 * expired (with a 30-second safety margin), allowing callers to pro-actively
 * refresh before the server rejects a request.</p>
 */
public final class TokenContainer {

    private final String accessToken;
    private final String tokenType;
    private final String refreshToken;
    private final Integer expiresIn;
    private final String scope;
    private final Instant obtainedAt;

    private TokenContainer(Builder builder) {
        this.accessToken = builder.accessToken;
        this.tokenType = builder.tokenType;
        this.refreshToken = builder.refreshToken;
        this.expiresIn = builder.expiresIn;
        this.scope = builder.scope;
        this.obtainedAt = builder.obtainedAt != null ? builder.obtainedAt : Instant.now();
    }

    /**
     * Returns the OAuth access token value.
     *
     * @return the access token; never {@code null}
     */
    public String getAccessToken() {
        return accessToken;
    }

    /**
     * Returns the token type (always {@code "Bearer"} for RFC 7523 responses).
     *
     * @return the token type; never {@code null}
     */
    public String getTokenType() {
        return tokenType;
    }

    /**
     * Returns the refresh token, if the authorization server issued one.
     *
     * @return the refresh token, or {@code null}
     */
    public String getRefreshToken() {
        return refreshToken;
    }

    /**
     * Returns the lifetime in seconds of the access token, as reported by the server.
     *
     * @return the lifetime in seconds, or {@code null} if not reported
     */
    public Integer getExpiresIn() {
        return expiresIn;
    }

    /**
     * Returns the granted scope(s), space-separated.
     *
     * @return the scope string, or {@code null}
     */
    public String getScope() {
        return scope;
    }

    /**
     * Returns the {@link Instant} at which this token was obtained.
     *
     * @return the time the token was obtained; never {@code null}
     */
    public Instant getObtainedAt() {
        return obtainedAt;
    }

    /**
     * Returns {@code true} if the access token has expired or is within 30 seconds of expiry.
     *
     * <p>If {@link #getExpiresIn()} is {@code null} (the server did not report a lifetime),
     * this method always returns {@code false}.</p>
     *
     * @return {@code true} if the token should be considered expired
     */
    public boolean isExpired() {
        if (expiresIn == null) {
            return false;
        }
        // 30-second safety margin
        Instant expiryWithMargin = obtainedAt.plusSeconds(expiresIn - 30);
        return Instant.now().compareTo(expiryWithMargin) >= 0;
    }

    /**
     * Creates a new {@link Builder}.
     *
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Fluent builder for {@link TokenContainer}.
     */
    public static final class Builder {

        private String accessToken;
        private String tokenType;
        private String refreshToken;
        private Integer expiresIn;
        private String scope;
        private Instant obtainedAt;

        private Builder() {
        }

        /** Sets the OAuth access token. */
        public Builder accessToken(String accessToken) {
            this.accessToken = accessToken;
            return this;
        }

        /** Sets the token type (e.g. {@code "Bearer"}). */
        public Builder tokenType(String tokenType) {
            this.tokenType = tokenType;
            return this;
        }

        /** Sets the optional refresh token. */
        public Builder refreshToken(String refreshToken) {
            this.refreshToken = refreshToken;
            return this;
        }

        /** Sets the lifetime in seconds. */
        public Builder expiresIn(Integer expiresIn) {
            this.expiresIn = expiresIn;
            return this;
        }

        /** Sets the scope string. */
        public Builder scope(String scope) {
            this.scope = scope;
            return this;
        }

        /**
         * Sets the time at which the token was obtained.
         * Defaults to {@link Instant#now()} if not set.
         */
        public Builder obtainedAt(Instant obtainedAt) {
            this.obtainedAt = obtainedAt;
            return this;
        }

        /** Builds a new {@link TokenContainer}. */
        public TokenContainer build() {
            return new TokenContainer(this);
        }
    }
}
