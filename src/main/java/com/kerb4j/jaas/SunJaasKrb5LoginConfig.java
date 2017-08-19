/*
 * Copyright 2015 the original author or authors.
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
package com.kerb4j.jaas;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import java.util.HashMap;
import java.util.Objects;

/**
 * Implementation of {@link Configuration} which uses Sun's JAAS
 * Krb5LoginModule.
 *
 * @author Nelson Rodrigues
 * @author Janne Valkealahti
 *
 */
public class SunJaasKrb5LoginConfig extends Configuration {

	private static final Logger LOG = LoggerFactory.getLogger(SunJaasKrb5LoginConfig.class);

	private String servicePrincipal;
	private String keyTabLocation;
	private Boolean useTicketCache = false;
	private Boolean isInitiator = false;
	private Boolean debug = false;
	private String keyTabLocationAsString;

	public void setServicePrincipal(String servicePrincipal) {
		this.servicePrincipal = servicePrincipal;
	}

	public void setKeyTabLocation(String keyTabLocation) {
		this.keyTabLocation = keyTabLocation;
	}

	public void setUseTicketCache(Boolean useTicketCache) {
		this.useTicketCache = useTicketCache;
	}

	public void setIsInitiator(Boolean isInitiator) {
		this.isInitiator = isInitiator;
	}

	public void setDebug(Boolean debug) {
		this.debug = debug;
	}

	public void afterPropertiesSet() throws Exception {
		assert Objects.nonNull(servicePrincipal) : "servicePrincipal must be specified";

		if (!useTicketCache) {
			assert Objects.nonNull(keyTabLocation) : "keyTabLocation must be specified when useTicketCache is false";
			if (keyTabLocationAsString.startsWith("file:")) {
				keyTabLocationAsString = keyTabLocationAsString.substring(5);
			}
		}
	}

	@Override
	public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
		HashMap<String, String> options = new HashMap<String, String>();

		options.put("principal", this.servicePrincipal);

		if (this.keyTabLocation != null) {
			options.put("useKeyTab", "true");
			options.put("keyTab", keyTabLocationAsString);
			options.put("storeKey", "true");
		}

		options.put("doNotPrompt", "true");

		if (useTicketCache) {
			options.put("useTicketCache", "true");
			options.put("renewTGT", "true");
		}

		options.put("isInitiator", this.isInitiator.toString());
		options.put("debug", this.debug.toString());

		return new AppConfigurationEntry[] { new AppConfigurationEntry("com.sun.security.auth.module.Krb5LoginModule",
				AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options), };
	}

}
