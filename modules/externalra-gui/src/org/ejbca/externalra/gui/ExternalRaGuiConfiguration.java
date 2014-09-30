/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.externalra.gui;

import java.io.File;
import java.net.URL;

import org.apache.commons.configuration.CompositeConfiguration;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.PropertiesConfiguration;
import org.apache.commons.configuration.SystemConfiguration;
import org.apache.commons.configuration.reloading.FileChangedReloadingStrategy;
import org.apache.log4j.Logger;

/** 
 * Configuration reader using Apache's Commons Configuration for the EJCBA External RA GUI.
 * 
 * @version $Id$
 */
public class ExternalRaGuiConfiguration {
	private static Logger log = Logger.getLogger(ExternalRaGuiConfiguration.class);   

	private static CompositeConfiguration config = null;

	/** This is a singleton so it's not allowed to create an instance explicitly */ 
	private ExternalRaGuiConfiguration() {}

	private static final String PROPERTIES_FILENAME = "externalra-gui.properties";

	private static final String PROPERTY_CONFIGALLOWEXTERNAL = "allow.external-dynamic.configuration";
	private static final String PROPERTY_CASERVICECERT       = "externalra-gui.caservicecert";
	private static final String PROPERTY_KEYSTORE            = "externalra-gui.keystore";
	private static final String PROPERTY_KEYSTOREPASSWORD    = "externalra-gui.keystorepassword";
	private static final String PROPERTY_ISSUERCHAIN         = "externalra-gui.issuerchain";
	private static final String PROPERTY_TIMEOUT             = "externalra-gui.timeout";

	private static final String PROPERTY_HELPURL             = "externalra-gui.helpurl";
	private static final String PROPERTY_EXPORTABLE          = "externalra-gui.exportable";
	
	/** @return the path to the certificate of the CA's External RA API service keystore. */
	public static String getCaServiceCertPath() {
		return instance().getString(PROPERTY_CASERVICECERT, "/home/jboss/extra-keys/externalra-caservice.pem");
	}

	/** @return the path to the client keystore. */
	public static String getKeyStorePath() {
		return instance().getString(PROPERTY_KEYSTORE, "/home/jboss/extra-keys/externalra-gui.p12");
	}

	/** @return the password for the client keystore. */
	public static String getKeyStorePassword() {
		return instance().getString(PROPERTY_KEYSTOREPASSWORD, "foo123");
	}

	/** @return the path to the CA certificate chain PEM for the CA that has issued the client and service keystores. */
	public static String getIssuerChainPath() {
		return instance().getString(PROPERTY_ISSUERCHAIN, "/home/jboss/extra-keys/externalra-gui.issuer.pem");
	}
	
	/** @return a URL the user should be redirected to for help or null if no URL was defined */
	public static String getHelpUrl() {
		return instance().getString(PROPERTY_HELPURL, null);
	}

	/** @return true if we should suggest that browser generated keys should not be exportable. */
	public static boolean getExportable() {
		return "true".equalsIgnoreCase(instance().getString(PROPERTY_EXPORTABLE, "true"));
	}

	/** @return the configured timeout in seconds */
	public static int getTimeOut() {
		int ret = 30;
		try {
			ret = Integer.parseInt(instance().getString(PROPERTY_TIMEOUT, "" + ret));
		} catch (NumberFormatException e) {
		}
		return ret;
	}

	/** @return preferred key specification. The RSA algorithm is assumed. */
	public static String getKeySpec() {
		return instance().getString("externalra-gui.keyspec", "2048");
	}

	private static Configuration instance() {
		if (config == null) {
			try {
				// Default values build into war file, this is last prio used if no of the other sources override this
				boolean allowexternal = Boolean.getBoolean(new PropertiesConfiguration(ExternalRaGuiConfiguration.class.getResource("/" + PROPERTIES_FILENAME)).getString(PROPERTY_CONFIGALLOWEXTERNAL, "false"));
				config = new CompositeConfiguration();
				PropertiesConfiguration pc;
				// Only add these config sources if we allow external configuration
				if (allowexternal) {
					// Override with system properties, this is prio 1 if it exists (java -Dscep.test=foo)
					config.addConfiguration(new SystemConfiguration());
					log.info("Added system properties to configuration source (java -Dfoo.prop=bar).");
					// Override with file in "application server home directory"/conf, this is prio 2
					File f1 = new File("conf/" + PROPERTIES_FILENAME);
					pc = new PropertiesConfiguration(f1);
					pc.setReloadingStrategy(new FileChangedReloadingStrategy());
					config.addConfiguration(pc);
					log.info("Added file to configuration source: "+f1.getAbsolutePath());
					// Override with file in "/etc/ejbca/conf/extra, this is prio 3
					File f2 = new File("/etc/ejbca/conf/extra/" + PROPERTIES_FILENAME);
					pc = new PropertiesConfiguration(f2);
					pc.setReloadingStrategy(new FileChangedReloadingStrategy());
					config.addConfiguration(pc);
					log.info("Added file to configuration source: "+f2.getAbsolutePath());	        		
				}
				// Default values build into war file, this is last prio used if no of the other sources override this
				URL url = ExternalRaGuiConfiguration.class.getResource("/" + PROPERTIES_FILENAME);
				pc = new PropertiesConfiguration(url);
				config.addConfiguration(pc);
				log.info("Added url to configuration source: "+url);
				log.info("Allow external re-configuration: "+allowexternal);
			} catch (ConfigurationException e) {
				log.error("Error intializing ExtRA Configuration: ", e);
			}
		} 
		return config;
	}
}
