/*
 * Copyright 2009-2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.kerb4j.server.spring;

import com.kerb4j.client.SpnegoClient;
import com.kerb4j.server.MultiPrincipalManager;
import org.springframework.core.io.Resource;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Simple implementation of MultiPrincipalManager that manages multiple principals
 * each with their own keytab files.
 * 
 * @since 2.0.0
 */
public class SimpleMultiPrincipalManager implements MultiPrincipalManager {
    
    private final Map<String, SpnegoClient> spnegoClients = new ConcurrentHashMap<>();
    
    /**
     * Add a principal with its keytab location.
     * 
     * @param principal the service principal name
     * @param keyTabLocation the location of the keytab file
     * @param acceptOnly whether this principal is accept-only
     */
    public void addPrincipal(String principal, Resource keyTabLocation, boolean acceptOnly) {
        try {
            String keyTabPath = keyTabLocation.getURL().toExternalForm();
            if (keyTabPath.startsWith("file:")) {
                keyTabPath = keyTabPath.substring(5);
            }
            SpnegoClient client = SpnegoClient.loginWithKeyTab(principal, keyTabPath, acceptOnly);
            spnegoClients.put(principal, client);
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize principal: " + principal, e);
        }
    }
    
    /**
     * Add a principal with its keytab location (default acceptOnly=true).
     * 
     * @param principal the service principal name
     * @param keyTabLocation the location of the keytab file
     */
    public void addPrincipal(String principal, Resource keyTabLocation) {
        addPrincipal(principal, keyTabLocation, true);
    }
    
    @Override
    public SpnegoClient getSpnegoClientForSPN(String spn) {
        return spnegoClients.get(spn);
    }
    
    @Override
    public boolean hasPrincipalForSPN(String spn) {
        return spnegoClients.containsKey(spn);
    }
    
    @Override
    public String[] getConfiguredSPNs() {
        return spnegoClients.keySet().toArray(new String[0]);
    }
}