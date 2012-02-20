/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
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

import java.math.BigInteger;

/**
 * External RA Key Recovery Request sub message used when the CA should recreate a keystore. Use the
 * reuseCertifcate flag to get the original certificate in the keystore.
 * 
 * Containing serial number of certificate with associated key to recover. It is possible to request
 * a new certificate with the original keys, or the original certificate, depending on the constructor
 * used.
 * 
 * Parameters inherited from the base class ExtRARequest is ignored.
 * 
 * @author philip
 * $Id$
 */
public class KeyRecoveryRequest extends ExtRARequest {

	public static final float LATEST_VERSION = (float) 1.0;
	
	static final int CLASS_TYPE = 4;
	
	// Public Constants.
	/**
	 * Constant specifying the generated key should be RSA
	 */
	public static final int KEYALG_RSA = 1;
	
	// Field constants
	private static final String PASSWORD              = "PASSWORD";
	private static final String REUSECERTIFICATE      = "REUSECERTIFICATE";
	private static final String ISSUERDN              = "ISSUERDN";
	private static final String CERTIFICATESN         = "CERTIFICATESN";

	
	private static final long serialVersionUID = 1L;
	
	/**
	 * Constructor that should be used when the original certificate should be returned in keystore
	 */
	public KeyRecoveryRequest(long requestId, String username,  String password,  String issuerdn, BigInteger certificatesn){    
		data.put(REQUESTID, Long.valueOf(requestId));
		data.put(CLASSTYPE, Integer.valueOf(CLASS_TYPE));
		data.put(VERSION, Float.valueOf(LATEST_VERSION));
		data.put(USERNAME, username);
		data.put(PASSWORD, password);
		data.put(REUSECERTIFICATE, Boolean.TRUE);
		data.put(ISSUERDN, issuerdn);
		data.put(CERTIFICATESN, certificatesn);
	}
	
	/**
	 * Constructor that should be used.when requesting a keystore with a new certificate with the same key.
	 */
	public KeyRecoveryRequest(long requestId, String username, String subjectDN, String subjectAltName, 
            String email, String subjectDirectoryAttributes, String endEntityProfileName, String certificateProfileName,
            String cAName, String password, String issuerdn, BigInteger certificatesn){
        super(requestId, username, subjectDN, subjectAltName, email, subjectDirectoryAttributes, endEntityProfileName, certificateProfileName,cAName);
		data.put(CLASSTYPE, Integer.valueOf(CLASS_TYPE));
		data.put(VERSION, Float.valueOf(LATEST_VERSION));
		data.put(PASSWORD, password);
		data.put(REUSECERTIFICATE, Boolean.FALSE);
		data.put(ISSUERDN, issuerdn);
		data.put(CERTIFICATESN, certificatesn);
	}

	/**
	 * Constructor used when laoded from a persisted state
	 */	
	public KeyRecoveryRequest(){}
	

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
	 * Returns if the original certificate should be in the recreated keystore
	 */
	public boolean getReUseCertificate(){
		return ((Boolean) data.get(REUSECERTIFICATE)).booleanValue();
	}
	
	/**
	 * Returns the issuer DN of the certificate which keystore should be recreated
	 */
	public String getIssuerDN(){
		return (String) data.get(ISSUERDN);
	}

	/**
	 * Returns the Certificate Serialnumber of the certificate which keystore should be recreated
	 */
	public BigInteger getCertificateSN(){
		return (BigInteger) data.get(CERTIFICATESN);
	}
	
	
	
	public void upgrade() {
		if(LATEST_VERSION != getVersion()){						
			data.put(VERSION, new Float(LATEST_VERSION));
		}
		
	}



}
