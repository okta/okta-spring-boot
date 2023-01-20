[<img src="https://www.okta.com/sites/default/files/Dev_Logo-01_Large-thumbnail.png" align="right" width="256px"/>](https://devforum.okta.com/)
[![Maven Central](https://img.shields.io/maven-central/v/com.okta.spring/okta-spring-boot-starter.svg)](https://search.maven.org/#search%7Cga%7C1%7Cg%3A%22com.okta.spring%22%20a%3A%22okta-spring-boot-starter%22)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Support](https://img.shields.io/badge/support-Developer%20Forum-blue.svg)](https://devforum.okta.com/)

Okta Spring Boot Starter
========================

Okta's Spring Boot Starter will enable your Spring Boot application to work with Okta via OAuth 2.0/OIDC.

<a href="https://foojay.io/today/works-with-openjdk">
   <img align="right" 
        src="https://github.com/foojayio/badges/raw/main/works_with_openjdk/Works-with-OpenJDK.png"   
        width="100">
</a>

## Release status

This library uses semantic versioning and follows Okta's [library version policy](https://developer.okta.com/code/library-versions/).

:heavy_check_mark: The current stable major version series is: 3.x

| Version      | Status                    |
|--------------| ------------------------- |
| 0.x.x, 1.x.x | :warning: Retired |
| 2.x.x        | :heavy_check_mark: Stable |
| 3.x.x        | :heavy_check_mark: Stable |

> Note: 3.x.x versions of the SDK would need JDK 17 or above.

## Spring Boot Version Compatibility

| Okta Spring Boot SDK Versions | Compatible Spring Boot Versions |
|-------------------------------|---------------------------------|
| 1.2.x                         | 2.1.x                           |
| 1.4.x                         | 2.2.x                           |
| 1.5.x                         | 2.4.x                           |
| 2.0.x                         | 2.4.x                           |
| 2.1.x                         | 2.7.x                           |
| 3.x.x                         | 3.0.x                           |
              
The latest release can always be found on the [releases page](https://github.com/okta/okta-spring-boot/releases).

## What you need

* An Okta account (sign up for a [forever-free developer account](https://developer.okta.com/signup/))
* An OIDC application (typically a 'Web' application)
* An [access token](https://developer.okta.com/docs/guides/implement-oauth-for-okta-serviceapp/get-access-token/)

## Quickstart

1. Create a Spring Boot application with [Spring initializr](https://start.spring.io/):

   ```bash
   curl https://start.spring.io/starter.tgz -d dependencies=web,okta -d baseDir=<<yourProjectName>> | tar -xzvf -
   cd <<yourProjectName>>
   ```
   
2. Configure it with [Okta CLI](https://github.com/oktadeveloper/okta-cli/blob/master/README.md):

   ```bash
   okta apps create
   ```

3. Run it:
 
   ```bash
   ./mvnw spring-boot:run
   ```

## Include the dependency

For Apache Maven:
```xml
<dependency>
    <groupId>com.okta.spring</groupId>
    <artifactId>okta-spring-boot-starter</artifactId>
    <version>${okta.springboot.version}</version>
</dependency>
```

For Gradle:
```groovy
compile 'com.okta.spring:okta-spring-boot-starter:${okta.springboot.version}'
```

where ${okta.springboot.version} is the latest published version in [Maven Central](https://search.maven.org/search?q=g:com.okta.spring%20a:okta-spring-boot-starter).

## Building API Applications - Resource Server

Are you building backend endpoints in order to support a client side application? If so follow along, otherwise skip to the next section.

### Configure your properties

You can configure your applications properties with environment variables, system properties, or configuration files. Take a look at the [Spring Boot documentation](https://docs.spring.io/spring-boot/docs/current/reference/html/boot-features-external-config.html) for more details.

Only these three properties are required for a web app:

| Property | Default | Required | Details |
|----------|---------|----------|---------|
| okta.oauth2.issuer     | N/A | ✅ | [Authorization Server](https://developer.okta.com/docs/how-to/set-up-auth-server.html) issuer URL, i.e.: https://{yourOktaDomain}/oauth2/default |
| okta.oauth2.clientId   | N/A | `*` | The Client Id of your Okta OIDC application |
| okta.oauth2.clientSecret   | N/A | `*` | The Client Secret of your Okta OIDC application |
| okta.oauth2.audience   | `api://default` |  | The audience of your [Authorization Server](/docs/how-to/set-up-auth-server.html) |
| okta.oauth2.groupsClaim | `groups` | | The claim key in the Access Token's JWT that corresponds to an array of the users groups. |

`*` Required when using [opaque access tokens](https://developer.okta.com/blog/2020/08/07/spring-boot-remote-vs-local-tokens).

### Create a Controller

The above client makes a request to `/hello-oauth`, you simply need to create a Spring Boot application and `Controller` to handle the response: 

```java
@SpringBootApplication
@RestController
public class DemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(DemoApplication.class, args);
	}

	@GetMapping("/hello-oauth")
	public String hello(Principal principal) {
	    return "Hello, " + principal.getName();
	}
}
```

### That's it!

To test things out you can use curl:

```bash
$ curl http://localhost:8080/hello-oauth \
   --header "Authorization: Bearer ${accessToken}"
```
The result should look something like:

```text
Hello, joe.coder@example.com
```

Okta's Spring Security integration will [parse the JWT access token](https://developer.okta.com/blog/2017/06/21/what-the-heck-is-oauth#oauth-flows) from the HTTP request's `Authorization: Bearer` header value.

Check out a minimal example that uses the [Okta Signin Widget and JQuery](examples/siw-jquery) or [this blog post](https://developer.okta.com/blog/2018/11/26/spring-boot-2-dot-1-oidc-oauth2-reactive-apis). 

### Spring MVC

1. Setup your MVC project by following [Quickstart](https://github.com/okta/okta-spring-boot#quickstart) section above.

2. Configure the URL mappings for handling `GET` and `POST` requests.

```java
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@RestController
public class DemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(DemoApplication.class, args);
	}

	@GetMapping("/")
	public String index(@AuthenticationPrincipal Jwt jwt) {
		return String.format("Hello, %s!", jwt.getSubject());
	}

	@GetMapping("/message")
	@PreAuthorize("hasAuthority('SCOPE_message:read')")
	public String message() {
		return "secret message";
	}

	@PostMapping("/message")
	@PreAuthorize("hasAuthority('SCOPE_message:write')")
	public String createMessage(@RequestBody String message) {
		return String.format("Message was created. Content: %s", message);
	}
}
```

**NOTE**: `message:read` and `message:write` used above in `@PreAuthorize` are OAuth scopes. If you are looking
to add custom scopes, refer to the [documentation](https://developer.okta.com/docs/guides/customize-authz-server/create-scopes/).
 
3. Configure your Resource Server either for JWT or Opaque Token validation by creating a `SecurityFilterChain` bean. If neither JWT nor Opaque Token is specified in configuration, JWT validation will be used by default.

```java
import com.okta.spring.boot.oauth.Okta;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
public class OAuth2ResourceServerSecurityConfiguration {
    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http.authorizeRequests()
            // allow anonymous access to the root page
            .antMatchers("/").permitAll()
            // all other requests
            .anyRequest().authenticated()
            .and()
            .oauth2ResourceServer().jwt(); // replace .jwt() with .opaqueToken() for Opaque Token case

        // Send a 401 message to the browser (w/o this, you'll see a blank page)
        Okta.configureResourceServer401ResponseBody(http);
        return http.build();
    }
}
```

Refer Spring Security documentation [here](https://docs.spring.io/spring-security/site/docs/current/reference/html5/#oauth2resourceserver) for more details on resource server configuration.

### Spring WebFlux

To configure a resource server when using Spring WebFlux, you need to use a couple annotations, and define a `SecurityWebFilterChain` bean.

```java
import com.okta.spring.boot.oauth.Okta;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@EnableWebFluxSecurity 
@EnableReactiveMethodSecurity 
public class SecurityConfiguration {

    @Bean 
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http
            .authorizeExchange()
                .anyExchange().authenticated()
                .and()
            .oauth2ResourceServer()
                .jwt();
                
        // Send a 401 message to the browser (w/o this, you'll see a blank page)
        Okta.configureResourceServer401ResponseBody(http);
                
        return http.build();
    }
}
```

If you want to support SSO and a resource server in the same application, you can do that too!

```java
@EnableWebFluxSecurity 
@EnableReactiveMethodSecurity 
public class SecurityConfiguration {

    @Bean 
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http
            .authorizeExchange()
                .anyExchange().authenticated()
                .and()
            .oauth2Login()
                .and()
            .oauth2ResourceServer()
                .jwt();
        return http.build();
    }
}
```

[Full Stack Reactive with Spring WebFlux, WebSockets, and React](https://developer.okta.com/blog/2018/09/25/spring-webflux-websockets-react) uses both SSO and a resource server. Its current code uses Spring Security's OIDC support. [Changing it to use the Okta Spring Starter](https://github.com/oktadeveloper/okta-spring-webflux-react-example/pull/11) reduces the lines of code quite a bit.

## Supporting server side applications - OAuth Code flow

Building a server side application and just need to redirect to a login page? This OAuth 2.0 code flow is for you.

### Create a Web App on Okta

To create a new OIDC app for Spring Boot on Okta:

1. Log in to your developer account, navigate to **Applications**, and click on **Add Application**.
2. Select **Web** and click **Next**. 
3. Give the application a name and add `http://localhost:8080/login/oauth2/code/okta` as a login redirect URI. 
4. Click **Done**.

### Configure your properties

You can configure your applications properties with environment variables, system properties, or configuration files. Take a look at the [Spring Boot documentation](https://docs.spring.io/spring-boot/docs/current/reference/html/boot-features-external-config.html) for more details.

| Property | Required | Details |
|----------|---------|---------|
| okta.oauth2.issuer     | true | [Authorization Server](/docs/how-to/set-up-auth-server.html) issuer URL, i.e.: https://{yourOktaDomain}/oauth2/default |
| okta.oauth2.clientId   | true | The Client Id of your Okta OIDC application |
| okta.oauth2.clientSecret   | true | The Client Secret of your Okta OIDC application |
| okta.oauth2.postLogoutRedirectUri | false | Set to a relative or absolute URI to enable [RP-Initiated (SSO) logout](https://developer.okta.com/blog/2020/03/27/spring-oidc-logout-options). |

**NOTE**: On setting **postLogoutRedirectUri**, you will be redirected to it after the end of your session. Therefore, this resource must be available anonymously, so be sure to add it to your `HttpSecurity` configuration.

<details>
<summary>See a <code>postLogoutRedirectUri</code> example:</summary>

```yaml
okta:
  oauth2:
    postLogoutRedirectUri: "http://localhost:8080/logout/callback"
```

```java
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {
    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests()
            // allow anonymous access to the root and logout pages
            .antMatchers("/", "/logout/callback").permitAll()
            // all other requests
            .anyRequest().authenticated();
        return http.build();
    }
}
```

</details>

### Create a simple application

Create a minimal Spring Boot application:

```java
@RestController
@SpringBootApplication
public class ExampleApplication {

    public static void main(String[] args) {
        SpringApplication.run(ExampleApplication.class, args);
    }

    @GetMapping("/")
    public String getMessageOfTheDay(@AuthenticationPrincipal OidcUser user) {
        return user.getName() + ", this message of the day is boring";
    }
}
```

If you want to allow anonymous access to specific routes you can add a `SecurityFilterChain` bean:

```java
@Configuration
static class SecurityConfig {
    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/my-anon-page").permitAll()
                .anyRequest().authenticated()
            .and().oauth2Client()
            .and().oauth2Login();
        return http.build();
    }
}
```

If you want to add custom claims to JWT tokens in your custom Authorization Server, see [Add Custom claim to a token](https://developer.okta.com/docs/guides/customize-tokens-returned-from-okta/add-custom-claim/) for more info.

You could then extract the attributes from the token by doing something like below:

```java
@RestController
public class ExampleController {

    @GetMapping("/email")
    public String getUserEmail(AbstractOAuth2TokenAuthenticationToken authentication) {
        // AbstractOAuth2TokenAuthenticationToken works for both JWT and opaque access tokens
        return (String) authentication.getTokenAttributes().get("sub");
    }
}
```

### Share Sessions Across Web Servers

The Authorization Code Flow (the typical OAuth redirect) uses sessions.  If you have multiple instances of your application, you must configure a [Spring Session](https://docs.spring.io/spring-session/docs/current/reference/html5/) implementation such as Redis, Hazelcast, JDBC, etc.


### That's it!

Open up <http://localhost:8080> in your favorite browser. 

You'll be redirected automatically to an Okta login page. Once you successfully login, you will be redirected back to your app and you'll see the message of the day!

This module integrates with Spring Security's OAuth support, all you need is the mark your application with the standard `@EnableOAuth2Client` annotation. 

## Use with Spring Native

You can use this starter with [Spring Native](https://github.com/spring-projects-experimental/spring-native). However, you will need to enable HTTPS in your main Spring Boot application class. For example:

```java
package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.nativex.hint.NativeHint;

@NativeHint(options = "--enable-https")
@SpringBootApplication
public class DemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }
}
```

You can also configure this setting in your `pom.xml` or `build.gradle`. See [Spring Native's documentation](https://docs.spring.io/spring-native/docs/current/reference/htmlsingle/#native-image-options) for more information.

## Proxy

If you're running your application (with this okta-spring-boot dependency) from behind a network proxy, you could setup properties for it in application.yml:
```yaml
okta:
  oauth2:
    proxy:
      host: "proxy.example.com"
      port: 7000
      username: "your-username"             # optional
      password: "your-secret-password"      # optional
```

or, add JVM args to your application like:

```bash
-Dokta.oauth2.proxy.host=proxy.example.com
-Dokta.oauth2.proxy.port=port
-Dokta.oauth2.proxy.username=your-username
-Dokta.oauth2.proxy.password=your-secret-password
```

or, you could set it programmatically like:

```java
System.setProperty("okta.oauth2.proxy.host", "proxy.example.com");
System.setProperty("okta.oauth2.proxy.port", "7000");
System.setProperty("okta.oauth2.proxy.username", "your-username");
System.setProperty("okta.oauth2.proxy.password", "your-secret-password");
```

See [here](https://docs.oracle.com/javase/8/docs/api/java/net/doc-files/net-properties.html) for the complete list of properties.

**Note:**  Spring WebFlux (and `WebClient`) does not support these properties. (See [spring-projects/spring-security#8882](https://github.com/spring-projects/spring-security/issues/8882)).

If you are running your Spring Boot App behind a reverse proxy, be sure to read [this](https://docs.spring.io/spring-boot/docs/current/reference/html/howto.html#howto-use-behind-a-proxy-server) guide.

# Inject the Okta Java SDK

To integrate the [Okta Java SDK](https://github.com/okta/okta-sdk-java) into your Spring Boot application you just need to add a dependency:

```xml
<dependency>
    <groupId>com.okta.spring</groupId>
    <artifactId>okta-spring-sdk</artifactId>
</dependency>
```

Then define the `okta.client.token` property. See [creating an API token](https://developer.okta.com/docs/api/getting_started/getting_a_token) for more info.

All that is left is to inject the client (`com.okta.sdk.client.Client`)! Take a look at [this post](https://spring.io/blog/2007/07/11/setter-injection-versus-constructor-injection-and-the-use-of-required/) for more info on the best way to inject your beans.

# Extra Credit

Want to build this project? 

Just clone it and run:

```bash
$ git clone https://github.com/okta/okta-spring-boot.git
$ cd okta-spring-boot
$ mvn install
```
