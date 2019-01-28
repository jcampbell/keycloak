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
import javax.ws.rs.core.MediaType;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.OIDCDiscoveryRepresentationProvider;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.models.KeycloakSession;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;

/**
 * @author <a href="mailto:james.p.campbell@gmail.com">James Campbell</a>
 */
public class InfinispanOIDCDiscoveryRepresentationProvider implements OIDCDiscoveryRepresentationProvider {

    private static final Logger log = Logger.getLogger(InfinispanOIDCDiscoveryRepresentationProvider.class);

    private final KeycloakSession session;

    private final Cache<String, OIDCDiscoveryRepresentationEntry> representationCache;

    public InfinispanOIDCDiscoveryRepresentationProvider(KeycloakSession session, Cache<String, OIDCDiscoveryRepresentationEntry> representationCache) {
        this.session = session;
        this.representationCache = representationCache;
    }

    public OIDCConfigurationRepresentation getOIDCConfigurationRepresentation(String issuer) throws IOException {
        OIDCDiscoveryRepresentationEntry entry = representationCache.get(issuer);
        if (entry != null) {
            OIDCConfigurationRepresentation rep = entry.getClientRepresentation();
            return rep;
        } else {
            SimpleHttp.Response response = SimpleHttp.doGet(issuer + "/.well-known/openid-configuration", session).header("accept", "application/json").asResponse();

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
                OIDCConfigurationRepresentation rep = JsonSerialization.readValue(response.asString(), OIDCConfigurationRepresentation.class);
                return rep;
            }
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
