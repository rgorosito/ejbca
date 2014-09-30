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

import org.cesecore.certificates.endentity.EndEntityType;

/**
 * External RA Request sub message containing userdata used to add or edit a user. Mostly used
 * with hard token issuing.
 * 
 * @author philip
 * $Id$
 */
public class EditUserRequest extends ExtRARequest {

	public static final float LATEST_VERSION = (float) 1.0;
	
	public static final String SOFTTOKENNAME_USERGENERATED = "USERGENERATED";
	public static final String SOFTTOKENNAME_P12           = "P12";
	public static final String SOFTTOKENNAME_JKS           = "JKS";
	public static final String SOFTTOKENNAME_PEM           = "PEM";	

	static final int CLASS_TYPE = 10;
	
	// Field constants
	private static final String PASSWORD              = "PASSWORD";
	private static final String STATUS                = "STATUS";
	private static final String TOKENNAME             = "TOKENNAME";
	private static final String TYPE                  = "TYPE";
	private static final String ISSUERNAME            = "ISSUERNAME";
	
	private static final long serialVersionUID = 1L;
	
	/**
	 * Default constructor that should be used.
	 * 
     * @param tokenname, the hard token profile if a hard token should be issued, p12 for a pkcs12 file etc.
	 * @param hardtokenissuername, the alias of the issuer or null if no hardtoken should be issued.
	 */
	public EditUserRequest(long requestId, String username, String subjectDN, String subjectAltName, 
            String email, String subjectDirectoryAttributes, String endEntityProfileName, String certificateProfileName,
            String cAName, String password, int status, int type, String tokenname, String hardtokenissuername){
        super(requestId, username, subjectDN, subjectAltName, email, subjectDirectoryAttributes, endEntityProfileName, certificateProfileName,cAName);
		data.put(CLASSTYPE, Integer.valueOf(CLASS_TYPE));
		data.put(VERSION, Float.valueOf(LATEST_VERSION));
		data.put(PASSWORD, password);
		data.put(STATUS, Integer.valueOf(status));
		data.put(TYPE, Integer.valueOf(type));
		data.put(TOKENNAME, tokenname);
		data.put(ISSUERNAME, hardtokenissuername);		
	}

	/**
	 * Constructor used when laoded from a persisted state
	 */	
	public EditUserRequest(){}
	

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
	 * Returns status (One of the EndEntityConstants.STATUS_ constants) used in this request.
	 */
	public int getStatus(){
		return ((Integer) data.get(STATUS)).intValue();
	}
	
	/**
	 * Returns tokenname used in this requests, either one of 
	 * "USERGENERATED", "P12", "JKS", "PEM" or the hame of the hardtokenprofile
	 */
	public String getTokenName(){
		return (String) data.get(TOKENNAME);
	}
	
	/**
	 * Returns hardtokenissuername. i.e alias of the issuer.
	 * returns null if not hardtoken should be issued.
	 */
	public String getHardTokenIssuerName(){
		return (String) data.get(ISSUERNAME);
	}	
	
	/**
	 * Returns the type settings of the user used in this request.
	 */	
	public EndEntityType getType(){
		return new EndEntityType(((Integer) data.get(TYPE)).intValue());
	}
	
	public void upgrade() {
		if(LATEST_VERSION != getVersion()){						
			data.put(VERSION, new Float(LATEST_VERSION));
		}
		
	}

}
