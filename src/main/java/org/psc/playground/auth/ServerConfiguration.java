package org.psc.playground.auth;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.psc.playground.auth.properties.PlaygroundAuthServerProperties;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.approval.TokenStoreUserApprovalHandler;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import java.security.KeyPair;
import java.util.Base64;

/**
 * To create a jwt with this configuration, you need to provide a basic auth request with the client-id as user and the
 * client-secret as password upon invoking POST /auth/token.<p>
 * <p>
 * Additionally you have to provide the grant_type=password, username=user and password=password (or other users from
 * the configured {@link AuthenticationManager}) as url-encoded form request parameters.
 * </p>
 * <p>
 * An example request can be found under src/main/resources.
 * </p>
 */
@Slf4j
@RequiredArgsConstructor
@Configuration
public class ServerConfiguration extends AuthorizationServerConfigurerAdapter {

    private final PlaygroundAuthServerProperties playgroundAuthServerProperties;

    private final AuthenticationManager authenticationManager;

    private final UserDetailsService userDetailsService;

    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Value("classpath:keystore.jks")
    private Resource keyStoreResource;

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        // @formatter:off
        clients.inMemory().withClient(playgroundAuthServerProperties.getClientId())
                .resourceIds("")
                .accessTokenValiditySeconds(60 * 10)
                .refreshTokenValiditySeconds(60 * 30)
                .authorizedGrantTypes("authorization_code", "password", "implicit", "refresh_token")
                .authorities("ROLE_CLIENT")
                .scopes("read", "write", "test")
                .secret(bCryptPasswordEncoder.encode(playgroundAuthServerProperties.getClientSecret()))
                .redirectUris(playgroundAuthServerProperties.getRedirectUris())
            .and()
            .withClient("my-less-trusted-autoapprove-client")
                .authorizedGrantTypes("implicit")
                .authorities("ROLE_CLIENT")
                .scopes("read")
                .autoApprove(true);
        // @formatter:on
    }

    @Bean
    public TokenStore tokenStore() {
        return new JwtTokenStore(jwtAccessTokenConverter());
    }

    @Bean
    public DefaultTokenServices defaultTokenServices(TokenStore tokenStore, ClientDetailsService clientDetailsService) {
        var defaultTokenServices = new DefaultTokenServices();
        defaultTokenServices.setTokenStore(tokenStore);
        defaultTokenServices.setSupportRefreshToken(true);
        defaultTokenServices.setClientDetailsService(clientDetailsService);
        defaultTokenServices.setTokenEnhancer(jwtAccessTokenConverter());
        return defaultTokenServices;
    }

    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        var jwtAccessTokenConverter = new PlaygroundJwtAccessTokenConverter();
        var keyPair = keyPair();
        log.info(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
        // usage with MAC-Key instead of RSA key pair -> jwtAccessTokenConverter.setSigningKey(),,,
        jwtAccessTokenConverter.setKeyPair(keyPair());
        return jwtAccessTokenConverter;
    }

    @Bean
    public TokenStoreUserApprovalHandler tokenStoreUserApprovalHandler(ClientDetailsService clientDetailsService) {
        var tokenStoreUserApprovalHandler = new TokenStoreUserApprovalHandler();
        tokenStoreUserApprovalHandler.setTokenStore(tokenStore());
        tokenStoreUserApprovalHandler.setRequestFactory(new DefaultOAuth2RequestFactory(clientDetailsService));
        return tokenStoreUserApprovalHandler;
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
        endpoints.tokenStore(tokenStore())
                .userDetailsService(userDetailsService)
                .tokenServices(defaultTokenServices(null, null))
                .userApprovalHandler(tokenStoreUserApprovalHandler(null))
                .authenticationManager(authenticationManager);
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer serverSecurityConfigurer) {
        serverSecurityConfigurer.realm("playground/client");
    }

    private KeyPair keyPair() {
        return keyStoreKeyFactory().getKeyPair(playgroundAuthServerProperties.getKeyPairAlias(),
                playgroundAuthServerProperties.getKeyPairPassword().toCharArray());
    }

    private KeyStoreKeyFactory keyStoreKeyFactory() {
        return new KeyStoreKeyFactory(new ClassPathResource(playgroundAuthServerProperties.getKeyStorePath()),
                playgroundAuthServerProperties.getKeyStorePassword().toCharArray());
    }

    private static class PlaygroundJwtAccessTokenConverter extends JwtAccessTokenConverter {
        @Override
        public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
            var enrichedAccessToken = super.enhance(accessToken, authentication);
            enrichedAccessToken.getAdditionalInformation().put("userInfo", "isTrusted");
            return enrichedAccessToken;

        }
    }

}
