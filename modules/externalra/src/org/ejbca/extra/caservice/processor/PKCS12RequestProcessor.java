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

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.extra.db.ExtRARequest;
import org.ejbca.extra.db.ISubMessage;
import org.ejbca.extra.db.PKCS12Request;
import org.ejbca.extra.db.PKCS12Response;

/**
 * 
 * @author tomas
 * @version $Id$
 */
public class PKCS12RequestProcessor extends MessageProcessor implements ISubMessageProcessor {
    private static final Logger log = Logger.getLogger(PKCS12RequestProcessor.class);

    public ISubMessage process(AuthenticationToken admin, ISubMessage submessage, String errormessage) {
    	if(errormessage == null){
    		return processExtRAPKCS12Request(admin, (PKCS12Request) submessage);
    	}else{
    		return new PKCS12Response(((ExtRARequest) submessage).getRequestId(), false, errormessage, null, null);
    	}
    }

    private ISubMessage processExtRAPKCS12Request(AuthenticationToken admin, PKCS12Request submessage) {
    	if (log.isDebugEnabled()) {
    		log.debug("Processing ExtRAPKCS12Request");
    	}
        final boolean usekeyrecovery  = globalConfigurationSession.getCachedGlobalConfiguration().getEnableKeyRecovery();
    	if (log.isDebugEnabled()) {
    		log.debug("Key recovery enabled: "+ usekeyrecovery);
    	}
		PKCS12Response retval = null;
        EndEntityInformation userdata = null;
		try{
            userdata = generateEndEntityInformation(admin, submessage);
            userdata.setPassword("foo123");
	      storeUserData(admin, userdata, false, EndEntityConstants.STATUS_INPROCESS);
	      
	      // Generate keys
	      KeyPair keys = generateKeys(submessage);
	      // Generate Certificate
	      X509Certificate cert = (X509Certificate) signSession.createCertificate(admin,submessage.getUsername(),"foo123", keys.getPublic());
	      
	      // Generate Keystore
	      // Fetch CA Cert Chain.	        
	      Certificate[] chain = (Certificate[]) MessageProcessor.getCACertChain(admin, submessage.getCAName(), false, caSession).toArray(new Certificate[0]);
	      String alias = CertTools.getPartFromDN(CertTools.getSubjectDN(cert), "CN");
	      if (alias == null){
	    	  alias = submessage.getUsername();
	      }	      	      
	      KeyStore pkcs12 = KeyTools.createP12(alias, keys.getPrivate(), cert, chain);
	      
	      // Store Keys if requested
	        if (usekeyrecovery && submessage.getStoreKeys()) {
	            // Save generated keys to database.
	            keyRecoverySession.addKeyRecoveryData(admin, cert, submessage.getUsername(), keys);
	        }

	      retval = new PKCS12Response(submessage.getRequestId(),true,null,pkcs12,submessage.getPassword());
          storeUserData(admin, userdata, false, EndEntityConstants.STATUS_GENERATED);
		} catch (ApprovalException ae) {
			// there might be an already saved approval for this user or a new approval will be created, 
			// so catch the exception thrown when this is the case and let the method return null to leave the message in the queue to be tried the next round.
			log.info("ApprovalException: "+ae.getMessage());
		} catch (WaitingForApprovalException wae) {
			// there might be an already saved approval for this user or a new approval will be created, 
			// so catch the exception thrown when this is the case and let the method return null to leave the message in the queue to be tried the next round.
			log.info("WaitingForApprovalException: "+wae.getMessage());
		}catch(Exception e){
			// We should end up here if an approval is rejected, or some other error occur. We will then send back a failed message
			log.error("Error processing ExtRAPKCS12Requset : ", e);
            if (userdata != null) {
                try {
                    storeUserData(admin, userdata, false, EndEntityConstants.STATUS_FAILED);                    
                } catch (Exception ignore) {/*ignore*/}
            }
			retval = new PKCS12Response(submessage.getRequestId(),false,e.getMessage(),null,null);
		}
		
		return retval;
	}
    
	private KeyPair generateKeys(PKCS12Request submessage) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
		KeyPair retval = null;
		String keyalg = null;
		if(submessage.getKeyAlg() == PKCS12Request.KEYALG_RSA){
			keyalg = AlgorithmConstants.KEYALGORITHM_RSA;
		} else if(submessage.getKeyAlg() == PKCS12Request.KEYALG_ECDSA){
				keyalg = AlgorithmConstants.KEYALGORITHM_ECDSA;
		} else {
			throw new NoSuchAlgorithmException("Wrong Key Algorithm specified.");
		}
		retval = KeyTools.genKeys(submessage.getKeySpec(), keyalg);

		return retval;
	}


}

