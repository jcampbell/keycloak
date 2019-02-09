package org.keycloak.broker.oidc;

import org.jboss.logging.Logger;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.representations.OIDCConfigurationRepresentation;

import java.io.IOException;
import java.util.Date;

/**
 * @author <a href="mailto:james.p.campbell@gmail.com">James Campbell</a>
 */
public class OIDCDiscoveryRepresentationLoader implements org.keycloak.broker.provider.OIDCDiscoveryRepresentationLoader {

    private static final Logger logger = Logger.getLogger(OIDCDiscoveryRepresentationLoader.class);

    private final KeycloakSession session;

    public OIDCDiscoveryRepresentationLoader(KeycloakSession session) {
        this.session = session;
    }

    public OIDCConfigurationRepresentation loadRepresentation(String issuer) throws IOException {
        SimpleHttp.Response response = SimpleHttp.doGet(issuer + "/.well-known/openid-configuration", session).header("accept", "application/json").asResponse();
        if ((response.getStatus() == 200) && (response.getFirstHeader("Content-Type").equalsIgnoreCase("application/json"))) {
            OIDCConfigurationRepresentation rep = response.asJson(OIDCConfigurationRepresentation.class);
            return rep;
        } else {
            throw new IOException("Invalid status or content-type while retrieving OpenID Connect configuration for issuer " + issuer);
        }
    }
}
