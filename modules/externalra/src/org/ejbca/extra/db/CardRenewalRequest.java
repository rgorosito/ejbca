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

import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;

/**
 * External RA card renewal sub message used when a users certificates on a PrimeCard smart card should be renewed.
 * 
 * Request to use to renew certificates on an EID smart card. The request is currently tailored against
 * EID card with one authentication certificate and one signature certificate. The certificates and two
 * pkcs10 requests are used as input.
 * 
 * When certificate renewal is requested the following steps are done:
 * * The two certificates are verified against the CA certificate
 * * The signatures on the requests are verified again the certificates (so the whole chain is verified)
 * * The certificate profile and CA Id for each certificate is taken from the hard token profile of the user,
 *   if there is a hard token profile defined for the user, otherwise it is taken from the
 *   users registration info.There is also a possibility to override the profile values in the request,
 *   this possibility is not used however.
 * * When the certificates have been created they are returned to in an ExtRACardRenewalResponse.
 * * The old certificates are not revoked, they can still be used to validate old signatures etc.
 * 
 * Parameters inherited from the base class ExtRARequset is ignored.
 * 
 * @version $Id$
 */
public class CardRenewalRequest extends ExtRARequest {
	private static final Log log = LogFactory.getLog(CardRenewalRequest.class);

	public static final float LATEST_VERSION = (float) 1.0;
	
	static final int CLASS_TYPE = 11;
	
	// Public Constants.
	
	// Field constants	
	private static final String AUTHCERT           = "AUTHCERT";
	private static final String SIGNCERT           = "SIGNCERT";
	private static final String AUTHPKCS10         = "AUTHPKCS10";
    private static final String SIGNPKCS10         = "SIGNPKCS10";
	private static final String AUTHPROFILE        = "AUTHPROFILE";
	private static final String SIGNPROFILE        = "SIGNPROFILE";
    private static final String AUTHCA             = "AUTHCA";
    private static final String SIGNCA             = "SIGNCA";

	private static final long serialVersionUID = 1L;
	
	/**
	 * Constructor revoking a specific certificate.
	 */
	public CardRenewalRequest(long requestId, String authcert, String signcert, String authreq, String signreq){    
		data.put(REQUESTID, Long.valueOf(requestId));
		data.put(CLASSTYPE, Integer.valueOf(CLASS_TYPE));
		data.put(VERSION, Float.valueOf(LATEST_VERSION));
        
		data.put(AUTHCERT, authcert);
		data.put(SIGNCERT, signcert);
        data.put(AUTHPKCS10, authreq);
		data.put(SIGNPKCS10, signreq);
		data.put(AUTHPROFILE, Integer.valueOf(-1));
		data.put(SIGNPROFILE, Integer.valueOf(-1));
		data.put(AUTHCA, Integer.valueOf(-1));
		data.put(SIGNCA, Integer.valueOf(-1));
	}

	/**
	 * Constructor revoking a specific certificate.
	 */
	public CardRenewalRequest(long requestId, String authcert, String signcert, String authreq, String signreq, int authProfile, int signProfile, int authCA, int signCA){    
		data.put(REQUESTID, Long.valueOf(requestId));
		data.put(CLASSTYPE, Integer.valueOf(CLASS_TYPE));
		data.put(VERSION, Float.valueOf(LATEST_VERSION));
        
		data.put(AUTHCERT, authcert);
		data.put(SIGNCERT, signcert);
        data.put(AUTHPKCS10, authreq);
		data.put(SIGNPKCS10, signreq);
		data.put(AUTHPROFILE, Integer.valueOf(authProfile));
		data.put(SIGNPROFILE, Integer.valueOf(signProfile));
		data.put(AUTHCA, Integer.valueOf(authCA));
		data.put(SIGNCA, Integer.valueOf(signCA));
	}
	/**
	 * Constructor used when laoded from a persisted state
	 */	
	public CardRenewalRequest(){}
	

	public float getLatestVersion() {
		return LATEST_VERSION;
	}

	/** Helper method */
	public Certificate getAuthCertificate() {
		return getCertificate(getAuthCert());
	}
	/** Helper method */
	public Certificate getSignCertificate() {
		return getCertificate(getSignCert());
	}
	private Certificate getCertificate(String certStr) {
		Certificate ret = null;
		if (StringUtils.isNotEmpty(certStr)) {
			try {
				ret = CertTools.getCertfromByteArray(Base64.decode(certStr.getBytes()));
			} catch (CertificateException e) {
				log.error("Error decoding certificate: ", e);
			}			
		}
		return ret;
	}
	
	/**
	 * Returns the profile for authentication cert.
	 */
	public int getAuthProfile(){
	   return ((Integer) data.get(AUTHPROFILE)).intValue();	
	}
	/**
	 * Returns the profile for signature cert.
	 */
	public int getSignProfile(){
	   return ((Integer) data.get(SIGNPROFILE)).intValue();	
	}
	/**
	 * Returns the CAid for authentication cert.
	 */
	public int getAuthCA(){
	   return ((Integer) data.get(AUTHCA)).intValue();	
	}
	/**
	 * Returns the CAid for signaturecert.
	 */
	public int getSignCA(){
	   return ((Integer) data.get(SIGNCA)).intValue();	
	}
	/**
	 * Returns the auth certificate
	 */
	public String getAuthCert(){
		return (String) data.get(AUTHCERT);
	}

	/**
	 * Returns the sign certificate
	 */
	public String getSignCert(){
		return (String) data.get(SIGNCERT);
	}
	
    /**
     * Returns the auth pkcs10 request
     */
    public String getAuthPkcs10(){
        return (String) data.get(AUTHPKCS10);
    }
    /**
     * Returns the sign pkcs10 request
     */
    public String getSignPkcs10(){
        return (String) data.get(SIGNPKCS10);
    }

	public void upgrade() {
        if(Float.compare(LATEST_VERSION, getVersion()) != 0) {            
			data.put(VERSION, new Float(LATEST_VERSION));
		}		
	}
}
