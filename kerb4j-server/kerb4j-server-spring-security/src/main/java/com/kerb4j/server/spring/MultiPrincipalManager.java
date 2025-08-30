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

/**
 * Interface for managing multiple service principals. This allows the server
 * to handle SPNEGO tokens for different service principals (SPNs) and select
 * the appropriate principal based on the target SPN in the token.
 * 
 * @since 2.0.0
 */
public interface MultiPrincipalManager {
    
    /**
     * Get the SpnegoClient for the specified service principal name.
     * 
     * @param spn the service principal name (e.g., "HTTP/www1.server.com@REALM")
     * @return the SpnegoClient configured for this principal, or null if not found
     */
    SpnegoClient getSpnegoClientForSPN(String spn);
    
    /**
     * Check if this manager has a principal configured for the given SPN.
     * 
     * @param spn the service principal name
     * @return true if a principal is configured for this SPN
     */
    boolean hasPrincipalForSPN(String spn);
    
    /**
     * Get all configured service principal names.
     * 
     * @return array of configured SPNs
     */
    String[] getConfiguredSPNs();
}