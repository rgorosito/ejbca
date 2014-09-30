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
package org.ejbca.extra.caservice.processor;

import java.math.BigInteger;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.util.CertTools;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.extra.db.ExtRARequest;
import org.ejbca.extra.db.ExtRAResponse;
import org.ejbca.extra.db.ISubMessage;
import org.ejbca.extra.db.RevocationRequest;

/**
 * 
 * @author tomas
 * @version $Id$
 */
public class RevocationRequestProcessor extends MessageProcessor implements ISubMessageProcessor {
    private static final Logger log = Logger.getLogger(RevocationRequestProcessor.class);

    public ISubMessage process(AuthenticationToken admin, ISubMessage submessage, String errormessage) {
		if(errormessage == null){
			return processExtRARevocationRequest(admin, (RevocationRequest) submessage);
		}else{
			return new ExtRAResponse(((ExtRARequest) submessage).getRequestId(), false, errormessage);
		}
    }

	private ISubMessage processExtRARevocationRequest(AuthenticationToken admin, RevocationRequest submessage) {
		log.debug("Processing ExtRARevocationRequest");
		ExtRAResponse retval = null;
		try {			 
			// If this is a message that does contain an explicit username, use it
			String username = submessage.getUsername();
			String issuerDN = submessage.getIssuerDN();
			BigInteger serno = submessage.getCertificateSN();
			if (StringUtils.isEmpty(issuerDN) && StringUtils.isEmpty(username)) {
				retval = new ExtRAResponse(submessage.getRequestId(),false,"Either username or issuer/serno is required");
			} else {
				if (StringUtils.isEmpty(username)) {
					username = certificateStoreSession.findUsernameByCertSerno(serno, CertTools.stringToBCDNString(issuerDN));
				} 
				if (username != null) {
					if ( (submessage.getRevokeAll() || submessage.getRevokeUser()) ) {
						// Revoke all users certificates by revoking the whole user
						EndEntityInformation vo = endEntityAccessSession.findUser(admin,username);
						if (vo != null) {
							endEntityManagementSession.revokeUser(admin,username, submessage.getRevocationReason());
							if (!submessage.getRevokeUser()) {
								// If we were not to revoke the user itself, but only the certificates, we should set back status
								endEntityManagementSession.setUserStatus(admin, username, vo.getStatus());
							}					
						} else {
						    log.info(InternalEjbcaResources.getInstance().getLocalizedMessage("ra.errorentitynotexist", username));
						    final String errmsg = InternalEjbcaResources.getInstance().getLocalizedMessage("ra.wrongusernameorpassword");
							retval = new ExtRAResponse(submessage.getRequestId(),false, errmsg);
						}
					} else {
						// Revoke only this certificate
						endEntityManagementSession.revokeCert(admin, serno, CertTools.stringToBCDNString(issuerDN), submessage.getRevocationReason());				
					}					
				} else {
					retval = new ExtRAResponse(submessage.getRequestId(),false,"User not found from issuer/serno: issuer='"+issuerDN+"', serno="+serno);					
				}
				// If we didn't create any other return value, it was a success
				if (retval == null) {
					retval = new ExtRAResponse(submessage.getRequestId(),true,null);					
				}
			}
		} catch (AuthorizationDeniedException e) {
			log.error("Error processing ExtRARevocationRequest : ", e);
			retval = new ExtRAResponse(submessage.getRequestId(),false, "AuthorizationDeniedException: " + e.getMessage());
		}catch(Exception e){
			log.error("Error processing ExtRARevocationRequest : ", e);
			retval = new ExtRAResponse(submessage.getRequestId(),false,e.getMessage());
		} 
		
		return retval;
	}
	
}

