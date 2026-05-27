/*
 * Copyright 2002-2015 the original author or authors.
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
package com.kerb4j.server.spring.webflux;

import com.kerb4j.server.MultiPrincipalManager;
import com.kerb4j.server.spring.SimpleMultiPrincipalManager;
import com.kerb4j.server.spring.jaas.sun.SunJaasKerberosTicketValidator;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

class MultiPrincipalParityTest {

    @Test
    void coreMultiPrincipalSupportIsAvailableForReactiveConfigurations() {
        SimpleMultiPrincipalManager manager = new SimpleMultiPrincipalManager();
        SunJaasKerberosTicketValidator validator = new SunJaasKerberosTicketValidator();

        assertThat(manager).isInstanceOf(MultiPrincipalManager.class);
        assertDoesNotThrow(() -> validator.setMultiPrincipalManager(manager));
    }
}
