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
package org.ejbca.extra.util;

import java.io.File;
import java.net.URL;

import org.apache.commons.configuration.CompositeConfiguration;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.PropertiesConfiguration;
import org.apache.commons.configuration.SystemConfiguration;
import org.apache.commons.configuration.reloading.FileChangedReloadingStrategy;
import org.apache.log4j.Logger;

/** This is a singleton. Used to configure common-configuration with our sources.
 * Use like this:
 * String value = ExtraConfiguration.instance().getString("my.conf.property.key");
 * See in-line comments below for the sources added to the configuration.
 * 
 * @author tomas
 * @version $Id$
 */
public class ExtraConfiguration {
	private static Logger log = Logger.getLogger(ExtraConfiguration.class);   

	private static CompositeConfiguration config = null;
	
	/** This is a singleton so it's not allowed to create an instance explicitly */ 
	private ExtraConfiguration() {}

	public static final String CONFIGALLOWEXTERNAL = "allow.external-dynamic.configuration";

	public static final String SCEPCERTPROFILEKEY = "scep.ra.certificateProfile";
	public static final String SCEPENTITYPROFILEKEY = "scep.ra.entityProfile";
	public static final String SCEPAUTHPWD = "scep.ra.authPwd";
	public static final String SCEPDEFAULTCA = "scep.ra.defaultCA";
	public static final String SCEPEDITUSER = "scep.ra.createOrEditUser";
	public static final String SCEPKEYSTOREPATH = "scep.ra.keyStorePath";
	public static final String SCEPKEYSTOREPWD = "scep.ra.keyStorePassword";

	public static final String PROPERTY_FILENAME = "scepra.properties";

	public static Configuration instance() {
		if (config == null) {
	        try {
	        	// Default values build into war file, this is last prio used if no of the other sources override this
	        	boolean allowexternal = Boolean.getBoolean(new PropertiesConfiguration(ExtraConfiguration.class.getResource("/" + PROPERTY_FILENAME)).getString(CONFIGALLOWEXTERNAL, "false"));

	        	config = new CompositeConfiguration();
	        	
	        	PropertiesConfiguration pc;
				// Only add these config sources if we allow external configuration
	        	if (allowexternal) {
		        	// Override with system properties, this is prio 1 if it exists (java -Dscep.test=foo)
		        	config.addConfiguration(new SystemConfiguration());
		        	log.info("Added system properties to configuration source (java -Dfoo.prop=bar).");
		        	
		        	// Override with file in "application server home directory"/conf, this is prio 2
		        	File f1 = new File("conf/" + PROPERTY_FILENAME);
		        	pc = new PropertiesConfiguration(f1);
		        	pc.setReloadingStrategy(new FileChangedReloadingStrategy());
		        	config.addConfiguration(pc);
		        	log.info("Added file to configuration source: "+f1.getAbsolutePath());
		        	
		        	// Override with file in "/etc/ejbca/conf/extra, this is prio 3
		        	File f2 = new File("/etc/ejbca/conf/extra/" + PROPERTY_FILENAME);
		        	pc = new PropertiesConfiguration(f2);
		        	pc.setReloadingStrategy(new FileChangedReloadingStrategy());
		        	config.addConfiguration(pc);
		        	log.info("Added file to configuration source: "+f2.getAbsolutePath());	        		
	        	}
	        	
	        	// Default values build into war file, this is last prio used if no of the other sources override this
	        	URL url = ExtraConfiguration.class.getResource("/" + PROPERTY_FILENAME);
	        	pc = new PropertiesConfiguration(url);
	        	config.addConfiguration(pc);
	        	log.info("Added url to configuration source: "+url);
	        	
	        	
	            log.info("Allow external re-configuration: "+allowexternal);
	        	// Test
	            log.debug("Using keystore path (1): "+config.getString(SCEPKEYSTOREPATH+".1"));
	            //log.debug("Using keystore pwd (1): "+config.getString(SCEPKEYSTOREPWD+".1"));
	            //log.debug("Using authPwd: "+config.getString(SCEPAUTHPWD));
	            log.debug("Using certificate profile: "+config.getString(SCEPCERTPROFILEKEY));
	            log.debug("Using entity profile: "+config.getString(SCEPENTITYPROFILEKEY));
	            log.debug("Using default CA: "+config.getString(SCEPDEFAULTCA));
	            log.debug("Create or edit user: "+config.getBoolean(SCEPEDITUSER));
	            log.debug("Mapping for CN=Scep CA,O=EJBCA Sample,C=SE: "+config.getString("CN=Scep CA,O=EJBCA Sample,C=SE"));	        	
	        } catch (ConfigurationException e) {
	        	log.error("Error intializing ExtRA Configuration: ", e);
	        }
		} 
		return config;
	}
}
