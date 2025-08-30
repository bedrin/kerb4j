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
package com.kerb4j.server.tomcat;

import com.kerb4j.client.SpnegoClient;
import com.kerb4j.server.MultiPrincipalManager;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Simple multi-principal manager for Tomcat that manages multiple service principals
 * each with their own keytab files.
 * 
 * @since 2.0.0
 */
public class TomcatMultiPrincipalManager implements MultiPrincipalManager {
    
    private final Map<String, SpnegoClient> spnegoClients = new ConcurrentHashMap<>();
    
    /**
     * Add a principal with its keytab location.
     * 
     * @param principal the service principal name
     * @param keyTabLocation the path to the keytab file
     */
    public void addPrincipal(String principal, String keyTabLocation) {
        try {
            SpnegoClient client = SpnegoClient.loginWithKeyTab(principal, keyTabLocation, true);
            spnegoClients.put(principal, client);
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize principal: " + principal, e);
        }
    }
    
    /**
     * Get the SpnegoClient for the specified service principal name.
     * 
     * @param spn the service principal name
     * @return the SpnegoClient configured for this principal, or null if not found
     */
    @Override
    public SpnegoClient getSpnegoClientForSPN(String spn) {
        return spnegoClients.get(spn);
    }
    
    /**
     * Check if this manager has a principal configured for the given SPN.
     * 
     * @param spn the service principal name
     * @return true if a principal is configured for this SPN
     */
    @Override
    public boolean hasPrincipalForSPN(String spn) {
        return spnegoClients.containsKey(spn);
    }
    
    /**
     * Get all configured service principal names.
     * 
     * @return array of configured SPNs
     */
    @Override
    public String[] getConfiguredSPNs() {
        return spnegoClients.keySet().toArray(new String[0]);
    }
}