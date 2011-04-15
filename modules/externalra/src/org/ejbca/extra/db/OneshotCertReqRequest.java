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

import org.bouncycastle.util.encoders.Base64;
import org.ejbca.core.model.SecConst;

/**
 * Certificate signing request message also containing userdata to use.
 * 
 * @version $Id$
 */
public class OneshotCertReqRequest extends ExtRARequest {

	private static final long serialVersionUID = 1L;
	
	static final int CLASS_TYPE = 17; // Must be unique to all submessage classes

	public static final float LATEST_VERSION = (float) 1.0;
	
	public static final int REQUEST_TYPE_PKCS10 = SecConst.CERT_REQ_TYPE_PKCS10;
	public static final int REQUEST_TYPE_PUBLICKEY = SecConst.CERT_REQ_TYPE_PUBLICKEY;
	public static final int REQUEST_TYPE_CRMF = SecConst.CERT_REQ_TYPE_CRMF;
	public static final int REQUEST_TYPE_SPKAC = SecConst.CERT_REQ_TYPE_SPKAC;
	
	public static final int RESPONSE_TYPE_CERTIFICATE       = SecConst.CERT_RES_TYPE_CERTIFICATE;
	public static final int RESPONSE_TYPE_PKCS7           	= SecConst.CERT_RES_TYPE_PKCS7;
	public static final int RESPONSE_TYPE_PKCS7WITHCHAIN    = SecConst.CERT_RES_TYPE_PKCS7WITHCHAIN;
	
	private static final String REQUEST_DATA  			= "responseData";
	private static final String REQUEST_TYPE  			= "requestType";
	private static final String RESPONSE_TYPE 			= "responseType";
	
	private static final String PASSWORD      			= "password";
	private static final String CERTIFICATESERIALNO 	= "certificateserialno";

	/** Constructor used when loaded from a persisted state */	
	public OneshotCertReqRequest() {}

    /**
     * Creates a new instance of OneshotCertReqRequest.
     *
     * @param requestId Unique request ID.
     * @param username The end entity name.
     * @param subjectDN The subject DN.
     * @param subjectAltName The subjectAltName or null.
     * @param email The e-mail address or null.
     * @param subjectDirectoryAttributes The subjectDirectoryAttributes or null.
     * @param endEntityProfileName The end entity profile name for instance "EMPTY".
     * @param certificateProfileName The certificate profile name for instance "ENDUSER".
     * @param cAName The CA name.
     * @param certificateSerialNo The certificate serial number to use or null.
     * @param password The end entity password to set.
     * @param requestType One of REQUEST_TYPE_...
     * @param requestData Encoded request data in requestType format.
     * @param responseType One of RESPONSE_TYPE_...
     */
	public OneshotCertReqRequest(long requestId, String username, 
			String subjectDN, String subjectAltName, String email, 
			String subjectDirectoryAttributes, String endEntityProfileName, 
			String certificateProfileName, String cAName, 
			BigInteger certificateSerialNo, String password, int requestType, 
			byte[] requestData, int responseType) {
		super(requestId, username, subjectDN, subjectAltName, email, 
				subjectDirectoryAttributes, endEntityProfileName, 
				certificateProfileName,cAName);
		data.put(VERSION, Float.valueOf(LATEST_VERSION));
		data.put(CLASSTYPE, Integer.valueOf(CLASS_TYPE));
		data.put(CERTIFICATESERIALNO, certificateSerialNo);
		data.put(PASSWORD, password);
		data.put(REQUEST_TYPE, Integer.valueOf(requestType));
		data.put(REQUEST_DATA, new String(Base64.encode(requestData)));
		data.put(RESPONSE_TYPE, Integer.valueOf(responseType));
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
	
	public BigInteger getCertificateSerialNumber() {
		return (BigInteger) data.get(CERTIFICATESERIALNO);
	}
}
