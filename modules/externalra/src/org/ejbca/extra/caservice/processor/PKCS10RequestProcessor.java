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

import java.security.cert.X509Certificate;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.cesecore.certificates.certificate.request.RequestMessageUtils;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.extra.db.ExtRARequest;
import org.ejbca.extra.db.ISubMessage;
import org.ejbca.extra.db.PKCS10Request;
import org.ejbca.extra.db.PKCS10Response;

/**
 * 
 * @version $Id$
 */
public class PKCS10RequestProcessor extends MessageProcessor implements ISubMessageProcessor {
    private static final Logger log = Logger.getLogger(PKCS10RequestProcessor.class);

    public ISubMessage process(AuthenticationToken admin, ISubMessage submessage, String errormessage) {
		if(errormessage == null){
			return processExtRAPKCS10Request(admin, (PKCS10Request) submessage);
		}else{
			return new PKCS10Response(((ExtRARequest) submessage).getRequestId(), false, errormessage, null, null);
		}
    }
    
    private ISubMessage processExtRAPKCS10Request(AuthenticationToken admin, PKCS10Request submessage) {
        if (log.isDebugEnabled()) {
            log.debug("Processing PKCS10Request");
        }
		PKCS10Response retval = null;
        EndEntityInformation userdata = null;
		try {
	      // Create a PKCS10
	      PKCS10RequestMessage pkcs10 = RequestMessageUtils.genPKCS10RequestMessage(submessage.getPKCS10().getBytes());
	      String password = pkcs10.getPassword();
	      
	      if (submessage.createOrEditUser()) {
	    	  // If we did not provide a password, set a default one
		      if (StringUtils.isEmpty(password)) {
		    	  log.debug("Empty password received, createOrEditUser=true so setting default password.");
		    	  password = "foo123";
		      }
	          userdata = generateEndEntityInformation(admin, submessage);
	          userdata.setPassword(password);
	          log.info("Creating/editing user: "+userdata.getUsername()+", with dn: "+userdata.getDN());
	    	  // See if the user already exists, if it exists and have status NEW or INPROCESS we will not try to change it
	    	  // This way we can use approvals. When a request first comes in, it is put for approval. When it is approved, 
	    	  // we will not try to change it again, because it is ready to be processed 
	          storeUserData(admin, userdata,false,EndEntityConstants.STATUS_INPROCESS );	    		  
	      }
	      if (StringUtils.isNotEmpty(password)) {
		      X509Certificate cert = (X509Certificate) signSession.createCertificate(admin,submessage.getUsername(),password, pkcs10.getRequestPublicKey());
		      byte[] pkcs7 = signSession.createPKCS7(admin, cert, true);
		      retval = new PKCS10Response(submessage.getRequestId(),true,null,cert,pkcs7);	    	  
	      } else {
	    	  // Will be caught below and a fail response created
	    	  throw new Exception("No challenge password received, can not use empty password for enrollment. Nothing processed.");
	      }
		} catch (ApprovalException ae) {
			// there might be an already saved approval for this user or a new approval will be created, 
			// so catch the exception thrown when this is the case and let the method return null to leave the message in the queue to be tried the next round.
			log.info("ApprovalException: "+ae.getMessage());
		} catch (WaitingForApprovalException wae) {
			// there might be an already saved approval for this user or a new approval will be created, 
			// so catch the exception thrown when this is the case and let the method return null to leave the message in the queue to be tried the next round.
			log.info("WaitingForApprovalException: "+wae.getMessage());
		}catch(Exception e){
			// We should end up here if an approval is rejected or approval execution failed, or some other error occur. We will then send back a failed message
		    // Since the request can not be processed any more, we will also set user status to failed, so that the user can be edited again.
		    // We do not end up here if the request is waiting for approval, then we end up above on the ApprovalExceptions.
			log.info("Error processing PKCS10Request: "+e.getMessage());
			if (log.isDebugEnabled()) {
				log.debug("Exception: ", e);
			}
            if (userdata != null) {
                try {
                    storeUserData(admin, userdata, false, EndEntityConstants.STATUS_FAILED);                    
                } catch (Exception ignore) {/*ignore*/}
            }
			retval = new PKCS10Response(submessage.getRequestId(), false, e.getMessage(), null, null);
		}
		
		return retval;
	}
}

