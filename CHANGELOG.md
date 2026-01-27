# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.1.0] - Unreleased

### ⚠️ BREAKING CHANGES

This release introduces breaking changes to support Spring Boot 4.x and Spring Security 7.x.

#### Java Version Requirement
- **Minimum Java version is now 17** (previously Java 11)
- Applications must be compiled and run on Java 17 or higher

#### Spring Framework Compatibility
- **Spring Boot 4.0.1+** is now required (previously Spring Boot 3.x)
- **Spring Security 7.0.2+** is now required (previously Spring Security 6.x)

#### Package Path Changes
Spring Boot 4.x relocated OAuth2 autoconfiguration classes. If you have imports referencing the old package paths, you must update them:

| Old Package (Spring Boot 3.x) | New Package (Spring Boot 4.x) |
|-------------------------------|-------------------------------|
| `org.springframework.boot.autoconfigure.security.oauth2.client.*` | `org.springframework.boot.security.oauth2.client.*` |
| `org.springframework.boot.autoconfigure.security.oauth2.resource.*` | `org.springframework.boot.security.oauth2.resource.*` |

**Affected classes include:**
- `OAuth2ClientProperties`
- `OAuth2ClientPropertiesMapper`
- `OAuth2ResourceServerProperties`
- And other related configuration classes

#### Spring Security 7.x API Changes
Spring Security 7.x deprecated the chained method style in favor of lambda DSL. The Okta Spring Boot Starter has been updated accordingly. If you have custom security configurations, update them to use the lambda DSL style:

```java
// Old style (deprecated)
http.authorizeRequests()
    .antMatchers("/").permitAll()
    .anyRequest().authenticated();

// New style (Spring Security 7.x)
http.authorizeHttpRequests(authorize -> authorize
    .requestMatchers("/").permitAll()
    .anyRequest().authenticated());
```

#### Removed Classes
- `DeferredLog` from Spring Boot has been removed. The library now uses SLF4J directly for logging during initialization.

### Added
- Support for Spring Boot 4.0.1
- Support for Spring Security 7.0.2
- Support for Spring Cloud 4.2.0
- Groovy 4.0.27 for Java 17 compatibility

### Changed
- Updated all OAuth2 package imports to Spring Boot 4.x paths
- Migrated Spring Security configurations to lambda DSL style
- Replaced `DeferredLog` with SLF4J `LoggerFactory` for deferred logging
- Updated `NamedOAuth2ServerAuthorizationRequestResolver` to use modern authorization request customizer pattern
- Updated exception handling for checked exceptions in `getOrderFromPath` method

### Fixed
- Javadoc HTML5 compatibility issues (table summary attributes, duplicate tags)
- PMD violations for unused method parameters
- Commons-logging banned dependency exclusions
- Integration test dependencies for OAuth2 autoconfigure classes

### Dependencies
- `spring-boot-dependencies`: 4.0.1
- `spring-cloud`: 4.2.0
- `okta-sdk`: 24.0.0
- `okta-commons`: 2.0.1
- `groovy`: 4.0.27
- `slf4j-api`: 2.0.17
- `mockito-core`: 5.18.0
- `testng`: 7.11.0

## [3.0.8] - 2025-XX-XX

### Fixed
- Bumped tomcat dependencies for security fixes
- Added OWASP configuration
- Resolved spring-security-core vulnerability

## Previous Releases

For changes in previous releases, see the [GitHub Releases](https://github.com/okta/okta-spring-boot/releases) page.
