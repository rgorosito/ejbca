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

import org.bouncycastle.util.encoders.Base64;

/**
 * Certificate signing request message.
 * 
 * @version $Id$
 */
public class CertificateRequestRequest extends ExtRARequest {

	private static final long serialVersionUID = 1L;
	
	static final int CLASS_TYPE = 15; // Must be unique to all submessage classes

	public static final float LATEST_VERSION = (float) 1.0;

	private static final String PASSWORD      = "password";
	private static final String REQUEST_DATA  = "responseData";
	private static final String REQUEST_TYPE  = "requestType";
	private static final String RESPONSE_TYPE = "responseType";
	
	public static final int REQUEST_TYPE_PKCS10 = 0;
	public static final int REQUEST_TYPE_CRMF   = 1;
	public static final int REQUEST_TYPE_KEYGEN = 2;
	public static final int RESPONSE_TYPE_ENCODED         = 0;
	public static final int RESPONSE_TYPE_PKCS7           = 1;
	public static final int RESPONSE_TYPE_UNSIGNEDPKCS7   = 2;

	/** Constructor used when loaded from a persisted state */	
	public CertificateRequestRequest() {}

	/**
	 * Create a new certificate signing request message.
	 * 
	 * @param requestId should be unique.
	 * @param username The end entity identifier
	 * @param password The shared secret
	 * @param requestType one of REQUEST_TYPE_..
	 * @param requestData encoded request data in requestType format
	 * @param responseType one of RESPONSE_TYPE_
	 */
	public CertificateRequestRequest(long requestId, String username, String password, int requestType, byte[] requestData, int responseType) {
		data.put(VERSION, Float.valueOf(LATEST_VERSION));
		data.put(CLASSTYPE, Integer.valueOf(CLASS_TYPE));
		data.put(REQUESTID, Long.valueOf(requestId));
		data.put(USERNAME, username);
		data.put(PASSWORD, password);
		data.put(REQUEST_TYPE, new Integer(requestType));
		data.put(REQUEST_DATA, new String(Base64.encode(requestData)));
		data.put(RESPONSE_TYPE, new Integer(responseType));
	}

	/** @see org.ejbca.core.model.IUpgradeableData#getLatestVersion() */
	public float getLatestVersion() { return LATEST_VERSION; }
	
	/** @see org.ejbca.core.model.IUpgradeableData#upgrade() */
	public void upgrade() {
		if (LATEST_VERSION != getVersion()) {						
			data.put(VERSION, new Float(LATEST_VERSION));
		}
	}

	/** @return the shared secret */
	public String getPassword() {
		return (String)data.get(PASSWORD);
	}

	/** @return one of REQUEST_TYPE_.. */
	public int getRequestType() {
		return ((Integer)data.get(REQUEST_TYPE)).intValue();
	}

	/** @return encoded request data in requestType format */
	public byte[] getRequestData() {
		return Base64.decode(((String)data.get(REQUEST_DATA)).getBytes());
	}

	/** @return one of RESPONSE_TYPE_.. */
	public int getResponseType() {
		return ((Integer)data.get(RESPONSE_TYPE)).intValue();
	}
}
