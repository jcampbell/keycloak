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

import org.keycloak.protocol.oidc.representations.OIDCConfigurationRepresentation;
import java.io.Serializable;

/**
 * @author <a href="mailto:james.p.campbell@gmail.com">James Campbell</a>
 */
public class OIDCDiscoveryRepresentationEntry implements Serializable {

    private final long lastRequestTime;

    private final OIDCConfigurationRepresentation configurationRepresentation;

    public OIDCDiscoveryRepresentationEntry(long lastRequestTime, OIDCConfigurationRepresentation configurationRepresentation) {
        this.lastRequestTime = lastRequestTime;
        this.configurationRepresentation = configurationRepresentation;
    }

    public long getLastRequestTime() { return lastRequestTime; }

    public OIDCConfigurationRepresentation getConfigurationRepresentation() { return configurationRepresentation; }
}