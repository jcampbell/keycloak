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
import org.keycloak.broker.provider.OIDCDiscoveryRepresentationLoader;
import org.keycloak.broker.provider.OIDCDiscoveryRepresentationProvider;
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

    public InfinispanOIDCDiscoveryRepresentationProvider(KeycloakSession session, Cache<String, OIDCDiscoveryRepresentationEntry> representationCache, long cacheTimeout) {
        this.session = session;
        this.representationCache = representationCache;
        this.refreshInterval = cacheTimeout;
    }

    public OIDCConfigurationRepresentation getOIDCConfigurationRepresentation(String issuer, OIDCDiscoveryRepresentationLoader loader, long cacheTimeout)
    {
        OIDCConfigurationRepresentation rep = null;
        long currentTime = new Date().getTime();
        long refreshInterval = cacheTimeout;
        if (this.refreshInterval < refreshInterval) {
            refreshInterval = this.refreshInterval;
        }

        OIDCDiscoveryRepresentationEntry entry = representationCache.get(issuer);
        try {
            if (entry != null) {
                long lastRequest = entry.getLastRequestTime();
                if ((currentTime - lastRequest) > refreshInterval) {
                    rep = loader.loadRepresentation(issuer);
                    representationCache.put(issuer, new OIDCDiscoveryRepresentationEntry(currentTime, rep));
                } else {
                    rep = entry.getConfigurationRepresentation();
                }
                return rep;
            }
            return loader.loadRepresentation(issuer);
        } catch (IOException e) {
            logger.warnf("Unable to load OIDC Configuration for issuer: %s.", issuer);
            logger.debug(e.getMessage());
        } finally {
            if (rep != null) {
                // If our request failed, but we still had a value in cache, return it with the warning in the log.
                return rep;
            } else {
                throw new RuntimeException("Unable to obtain OpenID Configuration for issuer " + issuer);
            }
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
