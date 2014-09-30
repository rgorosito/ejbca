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
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.util.CertTools;

/**
 * Response to a ExtRAPKCS10Request, contains a generated certificate if operation was successful. The
 * response also contains the same certificate in a PKCS7 file. The PKCS7 file is signed by the CA
 * and contains the full certificate chain of the issued certificate.
 * 
 * @author philip
 * $Id$
 */
public class PKCS10Response extends ExtRAResponse {

	private static final Log log = LogFactory.getLog(PKCS10Response.class);
	
	public static final float LATEST_VERSION = (float) 2.0;
	
	static final int CLASS_TYPE = 5; // Must be unique to all submessage classes
		// Field constants
	private static final String CERTIFICATE           = "CERTIFICATE";		
	private static final String PKCS7                 = "PKCS7";		
	
	private static final long serialVersionUID = 1L;

	/**
	 * Default constructor that should be used.
	 * 
	 * @param requestId
	 * @param success
	 * @param failinfo
	 * @param certificate the generated certificate, or null if request failed.
	 * @param pkcs7 the generated certificate in a pkcs7 signed by the CA andincluding the certificate chain, or null if request or pkcs7 generation failed.
	 *  
	 */
	public PKCS10Response(long requestId, boolean success, String failinfo, X509Certificate certificate, byte[] pkcs7) {
        super(requestId, success, failinfo);
        try {
    		data.put(CLASSTYPE, Integer.valueOf(CLASS_TYPE));
    		data.put(VERSION, Float.valueOf(LATEST_VERSION));
    		if(certificate != null) {
			  String certstring = new String(Base64.encode(certificate.getEncoded()));
			  data.put(CERTIFICATE, certstring);
    		}  
    		if (pkcs7 != null) {
    			String pkcs7str = new String(Base64.encode(pkcs7));
    			data.put(PKCS7, pkcs7str);
    		}
		} catch (CertificateEncodingException e) {
			log.error("Certificate encoding failed" , e);
		}
	}

	/**
	 * Constructor used when laoded from a persisted state
	 * 
	 */	
	public PKCS10Response(){}
	
	/**
	 * Returns the generated certifcate.
	 */
	public X509Certificate getCertificate(){
		CertificateFactory cf = CertTools.getCertificateFactory();
	    X509Certificate cert = null;
		try {
			String certStr = (String) data.get(CERTIFICATE);
			if (StringUtils.isNotEmpty(certStr)) {
				cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(Base64.decode(certStr.getBytes())));				
			}
		} catch (CertificateException e) {
			log.error("Error decoding certificate ", e);
		}
	    return cert;
	}
	
	/**
	 * Returns the generated certifcate, in PKCS7, signed by the CA, and including the CA certificate chain.
	 */
	public byte[] getCertificateAsPKCS7(){
		byte[] ret = null;
		String str = (String)data.get(PKCS7);
		if (str != null) {
			ret = Base64.decode(str.getBytes());
		}
		return ret;
	}

	public void upgrade() {
	}

	public float getLatestVersion() {
		return LATEST_VERSION;
	}
}
