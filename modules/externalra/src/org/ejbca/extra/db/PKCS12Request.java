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

/**
 * Ext RA PKCS12 Reguest sub message used when the CA should generate a keystore.
 * Contains a password used to protect the key-store, a key size and key algorithm.
 * 
 * @author philip
 * @version $Id$
 */
public class PKCS12Request extends BaseCertRequest {

	public static final float LATEST_VERSION = (float) 1.0;
	
	static final int CLASS_TYPE = 3;
	
	// Public Constants.
	/**
	 * Constant specifying the generated key shoulg be RSA
	 */
	public static final int KEYALG_RSA = 1;
	/**
	 * Constant specifying the generated key shoulg be ECDSA
	 */
	public static final int KEYALG_ECDSA = 2;
	
	// Field constants
	private static final String PASSWORD              = "PASSWORD";
	private static final String KEYALG                = "KEYALG";
	private static final String KEYSPEC               = "KEYSPEC";
	private static final String STOREKEYS             = "STOREKEYS";

	/** Kept for upgrade purposes 3.3 -> 3.4 */
	private static final String KEYSIZE               = "KEYSIZE";
	
	
	private static final long serialVersionUID = 1L;
	
	/**
	 * Default constructor that should be used.
	 */
	public PKCS12Request(long requestId, String username, String subjectDN, String subjectAltName, 
            String email, String subjectDirectoryAttributes, 
            String endEntityProfileName, String certificateProfileName,
            String cAName, String password, int keyAlg, String keySpec, boolean storeKeys){
        super(requestId, username, subjectDN, subjectAltName, email, subjectDirectoryAttributes, endEntityProfileName, certificateProfileName,cAName);
		data.put(CLASSTYPE, Integer.valueOf(CLASS_TYPE));
		data.put(VERSION, Float.valueOf(LATEST_VERSION));
		data.put(PASSWORD, password);
		data.put(KEYALG, Integer.valueOf(keyAlg));
		data.put(KEYSPEC, keySpec);
		data.put(STOREKEYS, Boolean.valueOf(storeKeys));
	}

	/**
	 * Constructor used when laoded from a persisted state
	 */	
	public PKCS12Request(){}
	

	public float getLatestVersion() {
		return LATEST_VERSION;
	}
	
	/**
	 * Returns the password used in this request.
	 */
	public String getPassword(){
		return (String) data.get(PASSWORD);
	}

	/**
	 * Returns the keyalg (One of the KEYALG_ constants) used in this request.
	 */
	public int getKeyAlg(){
		return ((Integer) data.get(KEYALG)).intValue();
	}
	
	/**
	 * Returns if the keys should be stored for later recovery
	 */
	public boolean getStoreKeys(){
		return ((Boolean) data.get(STOREKEYS)).booleanValue();
	}

	/**
	 * Returns the keyalg (One of the KEYALG_ constants) used in this request.
	 */	
	public String getKeySpec(){
		String ret = (String) data.get(KEYSPEC);
		if (ret == null) {
			// It may be an old message, then we will handle it anyway by reading the old property
			ret = ((Integer) data.get(KEYSIZE)).toString();
		}
		return ret;
	}
	
	public void upgrade() {
		if(LATEST_VERSION != getVersion()){						
			data.put(VERSION, new Float(LATEST_VERSION));
		}
		
	}
}
