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

import java.math.BigInteger;

import org.bouncycastle.util.encoders.Base64;
import org.cesecore.certificates.certificate.CertificateConstants;

/**
 * Certificate signing request message.
 * 
 * @version $Id$
 */
public class CertificateRequestRequest extends BaseCertRequest {

	private static final long serialVersionUID = 1L;
	
	static final int CLASS_TYPE = 15; // Must be unique to all submessage classes

	public static final float LATEST_VERSION = (float) 1.0;

	private static final String PASSWORD      = "password";
	private static final String CERTIFICATESERIALNO 	= "certificateserialno";

	/** This looks strange with request->response, but since it is constants it only looks strange in the hashmap (message). 
	 * We don't want to change it now since it would affect old clients */
	private static final String REQUEST_DATA  = "responseData";
	private static final String REQUEST_TYPE  = "requestType";
	private static final String RESPONSE_TYPE = "responseType";
	
	public static final int REQUEST_TYPE_PKCS10 = CertificateConstants.CERT_REQ_TYPE_PKCS10;
	public static final int REQUEST_TYPE_CRMF = CertificateConstants.CERT_REQ_TYPE_CRMF;
	public static final int REQUEST_TYPE_SPKAC = CertificateConstants.CERT_REQ_TYPE_SPKAC;
	public static final int REQUEST_TYPE_PUBLICKEY = CertificateConstants.CERT_REQ_TYPE_PUBLICKEY;
	
	/** A DER encoded certificate */
	public static final int RESPONSE_TYPE_CERTIFICATE       = CertificateConstants.CERT_RES_TYPE_CERTIFICATE;
	/** A PKCS7 signed by the CA */
	public static final int RESPONSE_TYPE_PKCS7           	= CertificateConstants.CERT_RES_TYPE_PKCS7;
	/** For requests where "createOrEdit==false" this gives an unsigned PKCS7, for "createOrEdit==true" a signed PKCS7 */
	public static final int RESPONSE_TYPE_PKCS7WITHCHAIN    = CertificateConstants.CERT_RES_TYPE_PKCS7WITHCHAIN;

	/** Kept for reasons to not change to much code in a small fix, should be removed during bigger refactoring */
	public static final int REQUEST_TYPE_KEYGEN = CertificateRequestRequest.REQUEST_TYPE_SPKAC;
	/** Kept for reasons to not change to much code in a small fix, should be removed during bigger refactoring */
	public static final int RESPONSE_TYPE_ENCODED = CertificateRequestRequest.RESPONSE_TYPE_CERTIFICATE;
	/** Kept for reasons to not change to much code in a small fix, should be removed during bigger refactoring */
	public static final int RESPONSE_TYPE_UNSIGNEDPKCS7 = CertificateRequestRequest.RESPONSE_TYPE_PKCS7WITHCHAIN;
	

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
		data.put(REQUEST_TYPE, Integer.valueOf(requestType));
		data.put(REQUEST_DATA, new String(Base64.encode(requestData)));
		data.put(RESPONSE_TYPE, Integer.valueOf(responseType));
	}

	/**
     * Creates a new instance of CertificateRequestRequest.
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
     * @param certificateSerialNo The certificate serial number to use or null, used to request a custom certificate serial number, if the CA allows this.
     * @param password The end entity password to set.
     * @param requestType One of REQUEST_TYPE_...
     * @param requestData Encoded request data in requestType format.
     * @param responseType One of RESPONSE_TYPE_...
     */
	public CertificateRequestRequest(long requestId, String username, 
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
