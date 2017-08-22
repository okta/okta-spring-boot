Run the example:
``` bash
mvn spring-boot:run \
 -Dokta.oauth.issuer=https://{yourOktaDomain}/oauth2/{yourAuthorizationServerId} \
 -Dokta.oauth.audience={yourAuthorizationServerAudience} \
 -Dokta.oauth.clientId={oauthClientId} \
 -Dokta.oauth.rolesClaim={customRoleClaim) # defaults to 'groups'
```

Browse to: http://localhost:8080
