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
package com.okta.spring.oauth.discovery

import org.springframework.http.HttpHeaders
import org.springframework.http.HttpInputMessage
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter
import org.testng.annotations.Test

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.equalTo

class DiscoveryMetadataTest {

    @Test
    void basicParseTest() {


        def converter = new MappingJackson2HttpMessageConverter()
        DiscoveryMetadata metadata = converter.read(DiscoveryMetadata, new HttpInputMessage() {

            @Override
            InputStream getBody() throws IOException {
                return DiscoveryMetadataTest.getResource("/discovery-test.json").openStream()
            }

            @Override
            HttpHeaders getHeaders() {
                return new HttpHeaders()
            }
        })

        assertThat metadata.issuer, equalTo("https://dev-259824.oktapreview.com/oauth2/ausar5cbq5TRRsbcJ0h7")
        assertThat metadata.authorizationEndpoint, equalTo("https://dev-259824.oktapreview.com/oauth2/ausar5cbq5TRRsbcJ0h7/v1/authorize")
        assertThat metadata.tokenEndpoint, equalTo("https://dev-259824.oktapreview.com/oauth2/ausar5cbq5TRRsbcJ0h7/v1/token")
        assertThat metadata.userinfoEndpoint, equalTo("https://dev-259824.oktapreview.com/oauth2/ausar5cbq5TRRsbcJ0h7/v1/userinfo")
        assertThat metadata.registrationEndpoint, equalTo("https://dev-259824.oktapreview.com/oauth2/v1/clients")
        assertThat metadata.jwksUri, equalTo("https://dev-259824.oktapreview.com/oauth2/ausar5cbq5TRRsbcJ0h7/v1/keys")
        assertThat metadata.responseTypesSupported, equalTo([
                "code",
                "id_token",
                "code id_token",
                "code token",
                "id_token token",
                "code id_token token"
        ])
        assertThat metadata.responseModesSupported, equalTo([
                "query",
                "fragment",
                "form_post",
                "okta_post_message"
        ])

        assertThat metadata.grantTypesSupported, equalTo([
                "authorization_code",
                "implicit",
                "refresh_token",
                "password"
        ])
        assertThat metadata.subjectTypesSupported, equalTo([
                "public"
        ])
        assertThat metadata.idTokenSigningAlgValuesSupported, equalTo([
                "RS256"
        ])
        assertThat metadata.scopesSupported, equalTo([
                "openid",
                "email",
                "profile",
                "address",
                "phone",
                "offline_access"
        ])
        assertThat metadata.tokenEndpointAuthMethodsSupported, equalTo([
                "client_secret_basic",
                "client_secret_post",
                "client_secret_jwt",
                "none"
        ])
        assertThat metadata.claimsSupported, equalTo([
                "iss",
                "ver",
                "sub",
                "aud",
                "iat",
                "exp",
                "jti",
                "auth_time",
                "amr",
                "idp",
                "nonce",
                "name",
                "nickname",
                "preferred_username",
                "given_name",
                "middle_name",
                "family_name",
                "email",
                "email_verified",
                "profile",
                "zoneinfo",
                "locale",
                "address",
                "phone_number",
                "picture",
                "website",
                "gender",
                "birthdate",
                "updated_at",
                "at_hash",
                "c_hash"
        ])
        assertThat metadata.codeChallengeMethodsSupported, equalTo([
                "S256"
        ])
        assertThat metadata.introspectionEndpoint, equalTo("https://dev-259824.oktapreview.com/oauth2/ausar5cbq5TRRsbcJ0h7/v1/introspect")
        assertThat metadata.introspectionEndpointAuthMethodsSupported, equalTo([
                "client_secret_basic",
                "client_secret_post",
                "client_secret_jwt",
                "none"
        ])
        assertThat metadata.revocationEndpoint, equalTo("https://dev-259824.oktapreview.com/oauth2/ausar5cbq5TRRsbcJ0h7/v1/revoke")
        assertThat metadata.revocationEndpointAuthMethodsSupported, equalTo([
                "client_secret_basic",
                "client_secret_post",
                "client_secret_jwt",
                "none"
        ])
        assertThat metadata.endSessionEndpoint, equalTo("https://dev-259824.oktapreview.com/oauth2/ausar5cbq5TRRsbcJ0h7/v1/logout")
    }
}
