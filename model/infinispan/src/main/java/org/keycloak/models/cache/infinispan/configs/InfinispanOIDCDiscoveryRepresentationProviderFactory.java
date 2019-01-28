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
import org.keycloak.Config;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.provider.OIDCDiscoveryRepresentationProvider;
import org.keycloak.broker.provider.OIDCDiscoveryRepresentationProviderFactory;
import org.keycloak.cluster.ClusterEvent;
import org.keycloak.cluster.ClusterProvider;
import org.keycloak.connections.infinispan.InfinispanConnectionProvider;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderEvent;
import org.keycloak.provider.ProviderEventListener;

/**
 * @author <a href="mailto:james.p.campbell@gmail.com">James Campbell</a>
 */
public class InfinispanOIDCDiscoveryRepresentationProviderFactory implements OIDCDiscoveryRepresentationProviderFactory<OIDCDiscoveryRepresentationProvider> {

    private static final Logger logger = Logger.getLogger(InfinispanOIDCDiscoveryRepresentationProviderFactory.class);

    public static final String PROVIDER_ID = "infinispan";

    public static final String OIDC_DISCOVERY_CLEAR_CACHE_EVENT = "OIDC_DISCOVERY_CLEAR_CACHE_EVENT";

    private volatile Cache<String, OIDCDiscoveryRepresentationEntry> configsCache;

    public InfinispanOIDCDiscoveryRepresentationProvider create(KeycloakSession session) {
        lazyInit(session);
        return new InfinispanOIDCDiscoveryRepresentationProvider(session, configsCache);
    }

    private void lazyInit(KeycloakSession session) {
        if (configsCache == null) {
            synchronized (this) {
                if (configsCache == null) {
                    logger.debug("Initializing OIDC Discovery Client Representation");
                    this.configsCache = session.getProvider(InfinispanConnectionProvider.class).getCache(InfinispanConnectionProvider.OIDC_CONNECT_DISCOVERY_CACHE);

                    ClusterProvider cluster = session.getProvider(ClusterProvider.class);
                    cluster.registerListener(OIDC_DISCOVERY_CLEAR_CACHE_EVENT, (ClusterEvent event) -> {
                        configsCache.clear();
                    });
                }
            }
        }
    }

    @Override
    public void init(Config.Scope config) {
        logger.debug("Initializing Infinispan OIDCDiscoveryRepresentation Provider");
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        factory.register(new ProviderEventListener() {

            @Override
            public void onEvent(ProviderEvent event) {
                if (configsCache == null) {
                    return;
                }

                if (event instanceof RealmModel.IdentityProviderUpdatedEvent) {
                    RealmModel.IdentityProviderUpdatedEvent eventt = (RealmModel.IdentityProviderUpdatedEvent) event;
                    IdentityProviderModel updatedProviderModel = eventt.getUpdatedIdentityProvider();
                    if (updatedProviderModel instanceof OIDCIdentityProviderConfig) {
                        // TODO: Consider allowing a per-issuer invalidation
                        // OIDCIdentityProviderConfig modell = (OIDCIdentityProviderConfig) updatedProviderModel;
                        // String issuer = modell.getIssuer();
                        // InfinispanOIDCDiscoveryRepresentationProvider provider = (InfinispanOIDCDiscoveryRepresentationProvider) eventt.getKeycloakSession().getProvider(OIDCDiscoveryRepresentationProvider.class, getId());
                        // provider.clearCacheEntry(issuer);
                        InfinispanOIDCDiscoveryRepresentationProvider provider = (InfinispanOIDCDiscoveryRepresentationProvider) eventt.getKeycloakSession().getProvider(OIDCDiscoveryRepresentationProvider.class, getId());
                        provider.clearCache();
                    }
                }
            }
        });
    }

    @Override
    public void close() { }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

}
