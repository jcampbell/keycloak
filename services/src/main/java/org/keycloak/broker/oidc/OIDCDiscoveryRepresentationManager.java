/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.broker.oidc;

import org.jboss.logging.Logger;
import org.keycloak.broker.provider.OIDCDiscoveryRepresentationProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.representations.OIDCConfigurationRepresentation;

import java.io.IOException;

/**
 * @author <a href="mailto:james.p.campbell@gmail.com">James Campbell</a>
 */
public class OIDCDiscoveryRepresentationManager {

    private static final Logger logger = Logger.getLogger(OIDCDiscoveryRepresentationManager.class);

    public static OIDCConfigurationRepresentation getOIDCConfigurationRepresentation(KeycloakSession session, String issuer, long cacheTimeout) {
        logger.debug("Attempting to get representation provider: OIDCDiscoveryRepresentationProvider");

        OIDCDiscoveryRepresentationProvider representationProvider = session.getProvider(OIDCDiscoveryRepresentationProvider.class);
        // Note: this can throw a RuntimeException in the event that no configuration representation can be
        // (or has been) resolved for the given issuer.
        logger.debugf("Current OIDC Representation provider is: %s", representationProvider.getClass().getCanonicalName());
        OIDCConfigurationRepresentation rep = representationProvider.getOIDCConfigurationRepresentation(issuer, new OIDCDiscoveryRepresentationLoader(session), cacheTimeout);
        if (rep == null) {
            logger.warnf("Unable to obtain OIDC Configuration for issuer %s", issuer);
            throw new RuntimeException("Unable to obtain OIDC Configuration for issuer" + issuer);
        }
        return rep;
    }
}
