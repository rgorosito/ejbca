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

/**
 * Request to use to revoke a generate certificate. Contains the IssuerDN, certificate SN and
 * revocation reason (One of the RevocationRequest.REVOKATION_REASON_ constants).
 * Optionally you can request revocation of the user in EJBCA, so the user can not get a new
 * certificate, when revoking the user, all the users certificates are revoked. This is requested by
 * setting the parameter revokeuser to true. You can also optionally request revocation of all the users
 * certificates, but without revoking the user itself, do this by setting revokall to true.
 *  
 * REVOKATION_REASON_REMOVEFROMCRL can be used to "unrevoke" a certificate that was previously revoked 
 * with reason REVOKATION_REASON_CERTIFICATEHOLD
 *
 * Parameters inherited from the base class ExtRARequest is ignored.
 * 
 * @author philip
 * $Id$
 */
public class RevocationRequest extends ExtRARequest {

	public static final float LATEST_VERSION = (float) 3.0;
	
	static final int CLASS_TYPE = 8;
	
	// Public Constants.
	/**
	 * Constant specifying type of revocation
	 */
    public static final int REVOKATION_REASON_UNSPECIFIED          = 0;
    public static final int REVOKATION_REASON_KEYCOMPROMISE        = 1;
    public static final int REVOKATION_REASON_CACOMPROMISE         = 2;
    public static final int REVOKATION_REASON_AFFILIATIONCHANGED   = 3;
    public static final int REVOKATION_REASON_SUPERSEDED           = 4;
    public static final int REVOKATION_REASON_CESSATIONOFOPERATION = 5;
    public static final int REVOKATION_REASON_CERTIFICATEHOLD      = 6;
    /** REVOKATION_REASON_REMOVEFROMCRL can be used to "unrevoke" a certificate that was previously revoked with reason REVOKATION_REASON_CERTIFICATEHOLD */
    public static final int REVOKATION_REASON_REMOVEFROMCRL        = 8;
    public static final int REVOKATION_REASON_PRIVILEGESWITHDRAWN  = 9;
    public static final int REVOKATION_REASON_AACOMPROMISE         = 10;
	
	// Field constants	
	private static final String REVOKATIONREASON      = "REVOCATIONREASON";
	private static final String ISSUERDN              = "ISSUERDN";
	private static final String CERTIFICATESN         = "CERTIFICATESN";
    private static final String USERNAME              = "USERNAME";
    /** If all the users certificates should be revoked */
	private static final String REVOKEALL             = "REVOKEALL";
    /** If the user should be revoked as well, and not only the certificates */
	private static final String REVOKEUSER            = "REVOKEUSER";

	private static final long serialVersionUID = 1L;
	
	/**
	 * Constructor revoking a specific certificate.
	 */
	public RevocationRequest(long requestId, String issuerdn, BigInteger certificatesn, int revocationReason){    
		data.put(REQUESTID, Long.valueOf(requestId));
		data.put(CLASSTYPE, Integer.valueOf(CLASS_TYPE));
		data.put(VERSION, Float.valueOf(LATEST_VERSION));
		data.put(ISSUERDN, issuerdn);
		data.put(CERTIFICATESN, certificatesn);
        data.put(USERNAME, "");
		data.put(REVOKATIONREASON, Integer.valueOf(revocationReason));
		data.put(REVOKEALL, Boolean.FALSE);
		data.put(REVOKEUSER, Boolean.FALSE);
	}
	/**
     * Constructor revoking a specific certificate, or optionally all certificates of the user owning this certificate, and optionally the user as well
	 */
	public RevocationRequest(long requestId, String issuerdn, BigInteger certificatesn, int revocationReason, boolean revokeuser, boolean revokeall){    
		data.put(REQUESTID, Long.valueOf(requestId));
		data.put(CLASSTYPE, Integer.valueOf(CLASS_TYPE));
		data.put(VERSION, Float.valueOf(LATEST_VERSION));
		data.put(ISSUERDN, issuerdn);
		data.put(CERTIFICATESN, certificatesn);
        data.put(USERNAME, "");
		data.put(REVOKATIONREASON, Integer.valueOf(revocationReason));
		data.put(REVOKEALL, Boolean.valueOf(revokeall));
		data.put(REVOKEUSER, Boolean.valueOf(revokeuser));
	}
    /**
     * Constructor revoking all of a users certificates, and optionally the user as well
     */
    public RevocationRequest(long requestId, String username, int revocationReason, boolean revokeuser){    
        data.put(REQUESTID, Long.valueOf(requestId));
        data.put(CLASSTYPE, Integer.valueOf(CLASS_TYPE));
        data.put(VERSION, Float.valueOf(LATEST_VERSION));
        data.put(ISSUERDN, "");
        data.put(CERTIFICATESN, new BigInteger("-1"));
        data.put(USERNAME, username);
        data.put(REVOKATIONREASON, Integer.valueOf(revocationReason));
        data.put(REVOKEALL, Boolean.TRUE);
        data.put(REVOKEUSER, Boolean.valueOf(revokeuser));
    }

	/**
	 * Constructor used when laoded from a persisted state
	 */	
	public RevocationRequest(){}
	

	public float getLatestVersion() {
		return LATEST_VERSION;
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
	
	/**
	 * Returns the revokation reason. One of the REVOKATION_REASON_ constants.
	 */
	public int getRevocationReason(){
		return ((Integer) data.get(REVOKATIONREASON)).intValue();
	}
	
	/**
	 * Returns the true is the all the users certificate should be revoked, false if only the given one.
	 */
	public boolean getRevokeAll(){
		return ((Boolean) data.get(REVOKEALL)).booleanValue();
	}

	/**
	 * Returns the true is the user should be revoked, false if only the certificates.
	 */
	public boolean getRevokeUser(){
		return ((Boolean) data.get(REVOKEUSER)).booleanValue();
	}
	
	public void upgrade() {
        if(Float.compare(LATEST_VERSION, getVersion()) != 0) {
            
            if(data.get(REVOKEALL) == null) {
                data.put(REVOKEALL, Boolean.FALSE);
            }
            if(data.get(REVOKEUSER) == null) {
                data.put(REVOKEUSER, Boolean.FALSE);
            }
            if(data.get(USERNAME) == null) {
                data.put(USERNAME, "");
            }
			data.put(VERSION, Float.valueOf(LATEST_VERSION));
		}
		
	}
}
