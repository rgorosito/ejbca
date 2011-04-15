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

package org.ejbca.extra.caservice.processor;

import org.apache.log4j.Logger;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.ExtendedInformation;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.extra.db.ExtRARequest;
import org.ejbca.extra.db.ISubMessage;
import org.ejbca.extra.db.OneshotCertReqRequest;
import org.ejbca.extra.db.OneshotCertReqResponse;
import org.ejbca.util.passgen.IPasswordGenerator;
import org.ejbca.util.passgen.PasswordGeneratorFactory;

/**
 * Process certificate signing requests editing the user in the same step similar to EjbcaWS.certificateRequest().
 * 
 * @author Markus Kilas
 * @version $Id$
 */
public class OneshotCertReqRequestProcessor extends MessageProcessor implements ISubMessageProcessor {

	/** Logger for this class. */
	private static final Logger LOG = Logger.getLogger(OneshotCertReqRequestProcessor.class);
		
	/** @see ISubMessageProcessor#process(Admin, ISubMessage, String) */
	public ISubMessage process(final Admin admin, final ISubMessage submessage, final String errormessage) {
		if (errormessage == null) {
			return processCertificateRequestRequest(admin, (OneshotCertReqRequest) submessage);
		} else {
			return new OneshotCertReqResponse(((ExtRARequest) submessage).getRequestId(), false, errormessage, null, null);
		}
	}
	
	/**
	 * Extracts the certificate signing request type and requests a new certificate using the provided credentials.
	 */
	private OneshotCertReqResponse processCertificateRequestRequest(final Admin admin, final OneshotCertReqRequest submessage) {
		LOG.debug("Processing CertificateRequestRequest");
	    try {
	    	if (LOG.isDebugEnabled()) {
	    		LOG.debug("CertReq for user '" + submessage.getUsername() + "'.");
	    	}
	        final UserDataVO userdatavo = getUserDataVO(admin, submessage);
	        final String requestData = new String(submessage.getRequestData()); 
	        final int requestTypeInt = submessage.getRequestType();
	        final int responseTypeInt = submessage.getResponseType();
	        
	        final String hardTokenSN = null;
	        final byte[] responseData = certificateRequestSession.processCertReq(
	        		admin, 
	        		userdatavo, 
	        		requestData, 
	        		requestTypeInt,
	        		hardTokenSN, 
	        		responseTypeInt); 
	        
			return new OneshotCertReqResponse(submessage.getRequestId(), 
					true, 
					null, 
					submessage.getResponseType(), 
					responseData);
	        
        } catch (Exception e) {
			LOG.debug("External RA request generated an error: " + e.getMessage());
			return new OneshotCertReqResponse(submessage.getRequestId(), false, "Error " + e.getMessage(), null, null);
		}	
	}
	
	private UserDataVO getUserDataVO(final Admin admin, final OneshotCertReqRequest submessage) throws ClassCastException, EjbcaException {
		final UserDataVO result = generateUserDataVO(admin, submessage);
		
		result.setStatus(UserDataConstants.STATUS_NEW);
		
		// Not yet supported: hardtokenissuerid
		// Not yet supported: custom start time
		// Not yet supported: custom end time
		// Not yet support: generic Custom ExtendedInformation
		
		if (submessage.getCertificateSerialNumber() != null) {
			ExtendedInformation ei = result.getExtendedinformation();
			if (ei == null) {
				ei = new ExtendedInformation(); 
			}
            ei.setCertificateSerialNumber(submessage.getCertificateSerialNumber());
            result.setExtendedinformation(ei);
        }
		
    	if (submessage.getPassword() == null) {
    		final IPasswordGenerator pwdgen = PasswordGeneratorFactory.getInstance(PasswordGeneratorFactory.PASSWORDTYPE_ALLPRINTABLE);
			final String pwd = pwdgen.getNewPassword(12, 12);									
    		result.setPassword(pwd);
    	} else {
    		result.setPassword(submessage.getPassword());
    	}
    	
    	return result;
    }
}
