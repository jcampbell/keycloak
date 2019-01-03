package org.keycloak.broker.oidc;

import com.fasterxml.jackson.databind.JsonNode;
import org.apache.http.HttpHeaders;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.models.KeycloakSession;
import javax.ws.rs.core.MediaType;
import java.io.IOException;


/**
 * @author <a href="mailto:james.p.campbell@gmail.com">James Campbell</a>
 *
 * This class provides a discoverConfig method that can be used to dynamically update the OpenID Connect Endpoints
 * from an OpenID Connect-enabled service provider.
 *
 * @see <a href="https://openid.net/specs/openid-connect-discovery-1_0.html">OpenID Connect Discovery</a>
 */
public class OIDCDiscoveryIdentityProvider extends OIDCIdentityProvider {

    public OIDCDiscoveryIdentityProvider(KeycloakSession session, OIDCIdentityProviderConfig config) {
        super(session, config);
    }

    public void discoverConfig(KeycloakSession session, OIDCIdentityProviderConfig config, String discoveryUrl) throws IOException {

        //TODO: Only make this request at some predefined interval
        SimpleHttp.Response response = SimpleHttp.doGet(discoveryUrl, session).header("accept", "application/json").asResponse();

        if (response.getStatus() == 200) {
            String contentType = response.getFirstHeader(HttpHeaders.CONTENT_TYPE);
            MediaType contentMediaType;
            try {
                contentMediaType = MediaType.valueOf(contentType);
            } catch (IllegalArgumentException ex) {
                contentMediaType = null;
            }
            if (contentMediaType == null || contentMediaType.isWildcardSubtype() || contentMediaType.isWildcardType()
                    || (!MediaType.APPLICATION_JSON_TYPE.isCompatible(contentMediaType))) {
                logger.warn("Unsupported content-type while retrieving OpenID Connect configuration.");
                throw new IOException("Unsupported content-type while retrieving OpenID Connect configuration.");
            }

            JsonNode googleOpenIdConfiguration = response.asJson();
            config.setIssuer(getJsonProperty(googleOpenIdConfiguration, "issuer"));
            config.setAuthorizationUrl(getJsonProperty(googleOpenIdConfiguration, "authorization_endpoint"));
            config.setTokenUrl(getJsonProperty(googleOpenIdConfiguration, "token_endpoint"));
            config.setUserInfoUrl(getJsonProperty(googleOpenIdConfiguration, "userinfo_endpoint"));

            //TODO: Add revocation support
            config.setJwksUrl(getJsonProperty(googleOpenIdConfiguration,"jwks_uri"));

            // TODO: Check requested scopes against scopes_supported
        } else {
            logger.warn("Error getting OpenID Connect configuration.");
            throw new IOException("Error getting OpenID Connect configuration.");
        }
    }
}
