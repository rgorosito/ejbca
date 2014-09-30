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
import java.security.cert.Certificate;
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
 * Response to an ExtRACardRenewalRequest. The response contains two certificates that can be
 * used to replace the old certificates on an EID smart card.
 * 
 * @author tomas
 * @version $Id$
 */
public class CardRenewalResponse extends ExtRAResponse {

	private static final Log log = LogFactory.getLog(CardRenewalResponse.class);
	
	public static final float LATEST_VERSION = (float) 1.0;
	
	static final int CLASS_TYPE = 12; // Must be unique to all submessage classes
		// Field constants
	private static final String AUTHCERT           = "AUTHCERT";		
    private static final String SIGNCERT           = "SIGNCERT";     
	
	private static final long serialVersionUID = 1L;

	/**
	 * Default constructor that should be used.
	 *  
	 */
	public CardRenewalResponse(long requestId, boolean success, String failinfo, Certificate authcert, Certificate signcert){
        super(requestId, success, failinfo);
        try {
    		data.put(CLASSTYPE, Integer.valueOf(CLASS_TYPE));
    		data.put(VERSION, Float.valueOf(LATEST_VERSION));
    		if(authcert != null){
			  String certstring = new String(Base64.encode(authcert.getEncoded()));
			  data.put(AUTHCERT, certstring);
    		}  
            if(signcert != null){
              String certstring = new String(Base64.encode(signcert.getEncoded()));
              data.put(SIGNCERT, certstring);
            }  
		} catch (CertificateEncodingException e) {
			log.error("Certificate encoding failed" , e);
		}
	}

	/**
	 * Constructor used when laoded from a persisted state
	 * 
	 */	
	public CardRenewalResponse(){}
	
	/**
	 * Returns the auth certificate base 64 encoded string.
	 */
	public String getAuthCert(){
        return (String)data.get(AUTHCERT);
	}
	/**
	 * Returns the generated sign certificate.
	 */
	public String getSignCert(){
        return (String)data.get(SIGNCERT);
	}
	/**
	 * Returns the generated auth certificate.
	 */
	public X509Certificate getAuthCertificate(){
        return getCert(AUTHCERT);
	}
    /**
     * Returns the generated sign certificate.
     */
    public X509Certificate getSignCertificate(){
        return getCert(SIGNCERT);
    }
    private X509Certificate getCert(String tag) {
        CertificateFactory cf = CertTools.getCertificateFactory();
        X509Certificate cert = null;
        try {
            String certStr = (String)data.get(tag);
            if (StringUtils.isNotEmpty(certStr)) {
                cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(Base64.decode((certStr).getBytes())));                
            }
        } catch (CertificateException e) {
            log.error("Error decoding certificate ", e);
        }
        return cert;
    }
	
	public void upgrade() {
        if(Float.compare(LATEST_VERSION, getVersion()) != 0) {            
            data.put(VERSION, new Float(LATEST_VERSION));
        }		
	}

	public float getLatestVersion() {
		return LATEST_VERSION;
	}
}
