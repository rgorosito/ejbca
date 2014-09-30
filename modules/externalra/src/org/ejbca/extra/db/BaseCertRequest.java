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

import org.apache.commons.lang.BooleanUtils;

/**
 * Base message for certificate request messages, simply contains common fields so we don't have to make copy and paste.
 *  
 * @version $Id$
 */
public class BaseCertRequest extends ExtRARequest {

	private static final float LATEST_VERSION = (float) 2.0;

	// Field constants
	private static final String CREATEOREDITEUSER   = "CREATEOREDITEUSER";

	private static final long serialVersionUID = 1L;
	
	/**
	 * Default constructor that should be used.
	 */
	public BaseCertRequest(long requestId, String username, String subjectDN, String subjectAltName, 
            String email, String subjectDirectoryAttributes,
            String endEntityProfileName, String certificateProfileName,
            String cAName){
        super(requestId, username, subjectDN, subjectAltName, email, subjectDirectoryAttributes, endEntityProfileName, certificateProfileName,cAName);
		data.put(CREATEOREDITEUSER, "false");
	}

	/**
	 * Constructor used when loaded from a persisted state
	 */	
	public BaseCertRequest(){}
	

	public float getLatestVersion() {
		return LATEST_VERSION;
	}
	
	/**
	 * Returns the CREATEUSER used in this request, and converts it to boolean
	 * @return true or false
	 */
	public boolean createOrEditUser(){
		String ret = (String)data.get(CREATEOREDITEUSER);
		return BooleanUtils.toBoolean(ret);
	}
	/**
	 * Sets the CREATEUSER used in this request
	 * @return true or false
	 */
	public void setCreateOrEditUser(boolean createUser){
		String create = BooleanUtils.toStringTrueFalse(createUser);
		data.put(CREATEOREDITEUSER, create);
	}
	
}
