package pakira.tech.authorization_server;

import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.UUID;

@SpringBootApplication
public class AuthorizationServerApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthorizationServerApplication.class, args);
	}

	@Bean
	public ApplicationRunner applicationRunner(RegisteredClientRepository registeredClientRepository, UserDetailsManager userDetailsManager) {
		return args -> {
			if(registeredClientRepository.findByClientId("public-client") == null) {
				RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
						.clientId("public-client")
						.clientSecret("secret")
						.clientAuthenticationMethod(ClientAuthenticationMethod.NONE) // authoprization code + PCKE
						.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
						.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
						.redirectUri("http://127.0.0.1:8081/login/oauth2/code/public-client")
						.postLogoutRedirectUri("http:127.0.0.1:8080")
						.scope(OidcScopes.OPENID)
						.scope(OidcScopes.PROFILE)
						.scope("offline_access")
						.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
						.build();

				registeredClientRepository.save(registeredClient);
			}

			if(!userDetailsManager.userExists("user")) {
				var user = User.withDefaultPasswordEncoder()
						.username("user")
						.password("password")
						.authorities("read", "write")
						.build();

				userDetailsManager.createUser(user);
			}




		};
	}
}
