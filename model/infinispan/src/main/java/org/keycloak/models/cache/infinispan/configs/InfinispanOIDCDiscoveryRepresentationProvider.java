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

package org.keycloak.models.cache.infinispan.configs;

import org.infinispan.Cache;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.OIDCDiscoveryRepresentationProvider;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.representations.OIDCConfigurationRepresentation;

import java.io.IOException;
import java.util.Date;

/**
 * @author <a href="mailto:james.p.campbell@gmail.com">James Campbell</a>
 */
public class InfinispanOIDCDiscoveryRepresentationProvider implements OIDCDiscoveryRepresentationProvider {

    private static final Logger logger = Logger.getLogger(InfinispanOIDCDiscoveryRepresentationProvider.class);

    private final KeycloakSession session;

    private final Cache<String, OIDCDiscoveryRepresentationEntry> representationCache;

    private long refreshInterval;

    public InfinispanOIDCDiscoveryRepresentationProvider(KeycloakSession session, Cache<String, OIDCDiscoveryRepresentationEntry> representationCache, long refreshInterval) {
        this.session = session;
        this.representationCache = representationCache;
        this.refreshInterval = refreshInterval;
    }

    public OIDCConfigurationRepresentation getOIDCConfigurationRepresentation(String issuer)
    {
        OIDCConfigurationRepresentation rep;
        long currentTime = new Date().getTime();

        OIDCDiscoveryRepresentationEntry entry = representationCache.get(issuer);

        if (entry != null) {
            long lastRequest = entry.getLastRequestTime();
            if ((currentTime - lastRequest) > this.refreshInterval) {
                rep = requestRepresentation(issuer);
                if (rep != null) {
                    // If our request failed, it's been logged by requestRepresentation, but return the last known
                    // representation anyway.
                    return rep;
                }
            }
            rep = entry.getConfigurationRepresentation();
            return rep;
        }
        rep = requestRepresentation(issuer);
        if (rep == null) {
            // If no successful configuration has ever been obtained, we need to raise a runtimeexception
            throw new RuntimeException("Unable to obtain OpenID Configuration for issuer " + issuer);
        }
        return rep;
    }

    private OIDCConfigurationRepresentation requestRepresentation(String issuer) {
        try {
            SimpleHttp.Response response = SimpleHttp.doGet(issuer + "/.well-known/openid-configuration", session).header("accept", "application/json").asResponse();
            if ((response.getStatus() == 200) && (response.getFirstHeader("Content-Type").equalsIgnoreCase("application/json"))) {
                OIDCConfigurationRepresentation rep = response.asJson(OIDCConfigurationRepresentation.class);
                representationCache.put(issuer, new OIDCDiscoveryRepresentationEntry(new Date().getTime(), rep));
                return rep;
            } else {
                logger.warnf("Invalid status or content-type while retrieving OpenID Connect configuration for issuer %s", issuer);
                return null;
            }
        } catch (IOException e) {
            logger.warnf("Error requesting OpenID Connect configuration for issuer %s", issuer);
            return null;
        }
    }

    @Override
    public void clearCache() {
        this.representationCache.clear();
    }

    @Override
    public void close() {

    }
}
