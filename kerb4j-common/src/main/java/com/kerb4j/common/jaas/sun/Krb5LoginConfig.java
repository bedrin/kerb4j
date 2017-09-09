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
package com.kerb4j.common.jaas.sun;

import com.sun.security.auth.module.Krb5LoginModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import java.util.HashMap;
import java.util.Map;

/**
 * Implementation of {@link Configuration} which uses Sun's JAAS
 * Krb5LoginModule.
 *
 * @author Nelson Rodrigues
 * @author Janne Valkealahti
 *
 */
public class Krb5LoginConfig extends Configuration {

	private static final Logger LOG = LoggerFactory.getLogger(Krb5LoginConfig.class);

	private static final String SUN_KRB5_LOGIN_MODULE_CLASS_NAME = Krb5LoginModule.class.getCanonicalName();
	private static final boolean SUN_KRB5_DEBUG = Boolean.getBoolean("sun.security.krb5.debug");

	private final AppConfigurationEntry[] appConfigurationEntries;

	public static Krb5LoginConfig createKeyTabClientConfig(String principal, String keyTabLocation) {
		Map<String, String> options = new HashMap<>();

		options.put("principal", principal);

		options.put("useKeyTab", "true");
		options.put("keyTab", keyTabLocation);
		options.put("storeKey", "true");

		options.put("doNotPrompt", "true");
		// TODO: add isInitiator true

		return new Krb5LoginConfig(options);
	}

	public static Krb5LoginConfig createTicketCacheClientConfig(String principal) {
		Map<String, String> options = new HashMap<>();

		options.put("renewTGT", "true");

		options.put("principal", principal);

		options.put("useTicketCache", "true");
		options.put("renewTGT", "true");

		options.put("doNotPrompt", "true");

		return new Krb5LoginConfig(options);
	}

	public static Krb5LoginConfig createUsernameAndPasswordClientConfig() {
		Map<String, String> options = new HashMap<>();

		options.put("storeKey", "true");

		return new Krb5LoginConfig(options);
	}

	protected Krb5LoginConfig(Map<String,String> additionalOptions) {
		Map<String, String> options = new HashMap<>();

		if (SUN_KRB5_DEBUG) {
			options.put("debug", "true");
		}

		options.putAll(additionalOptions);

		this.appConfigurationEntries = new AppConfigurationEntry[] {
				new AppConfigurationEntry(
						SUN_KRB5_LOGIN_MODULE_CLASS_NAME,
						AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
						options
				)
		};
	}

	@Override
	public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
		return appConfigurationEntries;
	}

}