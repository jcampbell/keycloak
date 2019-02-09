package org.keycloak.broker.provider;

import org.keycloak.protocol.oidc.representations.OIDCConfigurationRepresentation;

import java.io.IOException;

/**
 * @author <a href="mailto:james.p.campbell@gmail.com">James Campbell</a>
 */
public interface OIDCDiscoveryRepresentationLoader {
    OIDCConfigurationRepresentation loadRepresentation(String issuer) throws IOException;
}
