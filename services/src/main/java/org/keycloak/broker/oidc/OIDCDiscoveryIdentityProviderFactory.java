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
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.provider.OIDCDiscoveryRepresentationProvider;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.representations.OIDCConfigurationRepresentation;
import org.keycloak.protocol.oidc.representations.OIDCDiscoveryConfigurationRepresentation;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.io.InputStream;
import java.util.Map;

/**
 * @author <a href="mailto:james.p.campbell@gmail.com">James Campbell</a>
 */
public class OIDCDiscoveryIdentityProviderFactory extends AbstractIdentityProviderFactory<OIDCIdentityProvider> {

    private static final Logger logger = Logger.getLogger(OIDCDiscoveryIdentityProvider.class);

    public static final String PROVIDER_ID = "oidc discovery";

    @Override
    public String getName() {
        return "OpenID Connect v1.0 Discovery";
    }

    @Override
    public OIDCDiscoveryIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new OIDCDiscoveryIdentityProvider(session, new OIDCIdentityProviderConfig(model));
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public Map<String, String> parseConfig(KeycloakSession session, InputStream inputStream) {
        return parseOIDCDiscoveryConfig(session, inputStream);
    }

    protected static Map<String, String> parseOIDCDiscoveryConfig(KeycloakSession session, InputStream inputStream) {
        logger.debug("Parsing OIDC Discovery config");
        OIDCDiscoveryConfigurationRepresentation discoveryRep;
        try {
            discoveryRep = JsonSerialization.readValue(inputStream, OIDCDiscoveryConfigurationRepresentation.class);
        } catch (IOException e) {
            throw new RuntimeException("Failed to load openid connect metadata", e);
        }
        OIDCIdentityProviderConfig config = new OIDCIdentityProviderConfig(new IdentityProviderModel());
        OIDCConfigurationRepresentation rep = OIDCDiscoveryRepresentationManager.getOIDCConfigurationRepresentation(session, discoveryRep.getIssuer());

        config.setIssuer(rep.getIssuer());
        config.setLogoutUrl(rep.getLogoutEndpoint());
        config.setAuthorizationUrl(rep.getAuthorizationEndpoint());
        config.setTokenUrl(rep.getTokenEndpoint());
        config.setUserInfoUrl(rep.getUserinfoEndpoint());
        if (rep.getJwksUri() != null) {
            config.setValidateSignature(true);
            config.setUseJwksUrl(true);
            config.setJwksUrl(rep.getJwksUri());
        }
        return config.getConfig();
    }

}
