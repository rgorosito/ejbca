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
package org.ejbca.extra.db;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.KeyStore;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.util.encoders.Base64;

/**
 * Response to a ExtRAPKCS12Request and ExtRAKeyRecoveryRequest. Contains a Java Key Store
 * of type PKCS12 containing the certificate and private key if the operation was successful.
 * 
 * @author philip
 * $Id$
 */
public class PKCS12Response extends ExtRAResponse {

	public static final float LATEST_VERSION = (float) 1.0;
	
	private static final Log log = LogFactory.getLog(PKCS12Response.class);
	
	static final int CLASS_TYPE = 6; // Must be unique to all submessage classes
		// Field constants
	private static final String KEYSTORE           = "KEYSTORE";
		
	private static final long serialVersionUID = 1L;

	/**
	 * Default constructor that should be used.
	 *  
	 */
	public PKCS12Response(long requestId, boolean success, String failinfo, KeyStore pkcs12, String password){
        super(requestId, success, failinfo);
        try {
    		data.put(CLASSTYPE, Integer.valueOf(CLASS_TYPE));
    		data.put(VERSION, Float.valueOf(LATEST_VERSION));
    		if(pkcs12 != null){
        	  ByteArrayOutputStream baos = new ByteArrayOutputStream();
        	  pkcs12.store(baos, password.toCharArray());        
			  String keystorestring = new String(Base64.encode(baos.toByteArray()));    		  
			  baos.close();
			  data.put(KEYSTORE, keystorestring);
    	    }
		} catch (Exception e) {
			log.error("KeyStore encoding failed" , e);
		}
	}

	/**
	 * Constructor used when loaded from a persisted state
	 */	
	public PKCS12Response(){}
	
	/**
	 * Returns the generated keystore.
	 * @param password used to unlocked the keystore
	 */
	public KeyStore getKeyStore(String password){
        KeyStore ks = null;
		try {
			ks = KeyStore.getInstance("PKCS12", "BC");
			InputStream in = new ByteArrayInputStream(Base64.decode(((String) data.get(KEYSTORE)).getBytes()));
	        ks.load(in, password.toCharArray());
	        in.close();
		} catch (Exception e) {
			log.error("KeyStore decoding failed" , e);
		}         
        
        return ks;			    
	}
	
	public void upgrade() {
	}

	public float getLatestVersion() {
		return LATEST_VERSION;
	}
}
