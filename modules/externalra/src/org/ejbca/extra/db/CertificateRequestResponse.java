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

import org.bouncycastle.util.encoders.Base64;

/**
 * Certificate signing request response.
 * 
 * @version $Id$
 */
public class CertificateRequestResponse extends ExtRAResponse {

	private static final long serialVersionUID = 1L;

	static final int CLASS_TYPE = 16; // Must be unique to all submessage classes

	public static final float LATEST_VERSION = (float) 1.0;

	private static final String RESPONSE_DATA = "responseData";
	private static final String RESPONSE_TYPE = "requestType";
	
	/** Constructor used when loaded from a persisted state */	
	public CertificateRequestResponse() {}

	/**
	 * Create a new message.
	 * 
	 * @param requestId should be the same unique identifier as in the request.
	 * @param success true if the request was successful
	 * @param failinfo description of the error if the request was unsuccessful
	 * @param responseType One of the CertificateRequestRequest.RESPONSE_TYPE_ constants
	 * @param responseData The request
	 * 
	 * @see org.ejbca.extra.db.ExtRAResponse#ExtRAResponse(long, boolean, String)
	 */
	public CertificateRequestResponse(long requestId, boolean success, String failinfo, Integer responseType, byte[] responseData) {
        super(requestId, success, failinfo);
		data.put(VERSION, Float.valueOf(LATEST_VERSION));
		data.put(CLASSTYPE, Integer.valueOf(CLASS_TYPE));
		data.put(RESPONSE_TYPE, responseType);
		if (responseData != null) {
			data.put(RESPONSE_DATA, new String(Base64.encode(responseData)));
		} else {
			data.put(RESPONSE_DATA, null);
		}
	}
	
	/** @see org.ejbca.core.model.IUpgradeableData#getLatestVersion() */
	public float getLatestVersion() { return LATEST_VERSION; }
	
	/** @see org.ejbca.core.model.IUpgradeableData#upgrade() */
	public void upgrade() {
		if (LATEST_VERSION != getVersion()) {						
			data.put(VERSION, new Float(LATEST_VERSION));
		}
	}

	/** @return the encoded certificate(s) */
	public byte[] getResponseData() {
		return Base64.decode(((String)data.get(RESPONSE_DATA)).getBytes());
	}

	/** @return one of CertificateRequestRequest.RESPONSE_TYPE_.. */
	public int getResponseType() {
		return ((Integer)data.get(RESPONSE_TYPE)).intValue();
	}
}
