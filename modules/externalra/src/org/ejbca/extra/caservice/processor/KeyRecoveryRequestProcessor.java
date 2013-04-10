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

import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.model.keyrecovery.KeyRecoveryData;
import org.ejbca.extra.db.ExtRARequest;
import org.ejbca.extra.db.ExtRAResponse;
import org.ejbca.extra.db.ISubMessage;
import org.ejbca.extra.db.KeyRecoveryRequest;
import org.ejbca.extra.db.PKCS12Response;

/**
 * 
 * @version $Id$
 */
public class KeyRecoveryRequestProcessor extends MessageProcessor implements ISubMessageProcessor {
    private static final Logger log = Logger.getLogger(KeyRecoveryRequestProcessor.class);

    public ISubMessage process(AuthenticationToken admin, ISubMessage submessage, String errormessage) {
    	if(errormessage == null){
    		return processExtRAKeyRecoveryRequest(admin, (KeyRecoveryRequest) submessage);
    	}else{
    		return new ExtRAResponse(((ExtRARequest) submessage).getRequestId(), false, errormessage);
    	}
    }

    private ISubMessage processExtRAKeyRecoveryRequest(AuthenticationToken admin, KeyRecoveryRequest submessage) {
		log.debug("Processing ExtRAKeyRecoveryRequest");
		PKCS12Response retval = null;
		try{
			
			EndEntityInformation endEntity = null;
			
			if(submessage.getReUseCertificate()){
				endEntity = endEntityAccessSession.findUser(admin,submessage.getUsername());
			}else{
			  endEntity = generateEndEntityInformation(admin, submessage);
			  endEntity.setPassword("foo123");
			}
			
			// Get KeyPair
			keyRecoverySession.unmarkUser(admin,submessage.getUsername());
			X509Certificate orgcert = (X509Certificate) certificateStoreSession.findCertificateByIssuerAndSerno(CertTools.stringToBCDNString(submessage.getIssuerDN()), submessage.getCertificateSN());
			if(orgcert == null){
				throw new EjbcaException("Error in Key Recovery Request, couldn't find specified certificate");
			}
			if(!endEntityManagementSession.prepareForKeyRecovery(admin, endEntity.getUsername(), endEntity.getEndEntityProfileId(), orgcert)){
				throw new EjbcaException("Error in Key Recovery Request, no keys saved for specified request");
			}
			KeyRecoveryData keyData = keyRecoverySession.recoverKeys(admin, submessage.getUsername(), endEntity.getEndEntityProfileId());
			if(keyData == null){
				throw new EjbcaException("Error in Key Recovery Request, no keys saved for specified request");
			}			
			KeyPair savedKeys = keyData.getKeyPair();
			
			X509Certificate cert = null;	
			if(submessage.getReUseCertificate()){	
				cert= orgcert;
				
			}else{
				storeUserData(admin, endEntity,false, EndEntityConstants.STATUS_INPROCESS);
				
				// Generate Certificate
				cert = (X509Certificate) signSession.createCertificate(admin,submessage.getUsername(),"foo123", savedKeys.getPublic());			  
			}			
			
			// Generate Keystore
			// Fetch CA Cert Chain.	        
			int caid = CertTools.stringToBCDNString(cert.getIssuerDN().toString()).hashCode(); 
			Certificate[] chain = (Certificate[]) caSession.getCAInfo(admin, caid).getCertificateChain().toArray(new Certificate[0]);
			String alias = CertTools.getPartFromDN(CertTools.getSubjectDN(cert), "CN");
			if (alias == null){
				alias = submessage.getUsername();
			}	      	      
			KeyStore pkcs12 = KeyTools.createP12(alias, savedKeys.getPrivate(), cert, chain);
			
			retval = new PKCS12Response(submessage.getRequestId(),true,null,pkcs12,submessage.getPassword());
			
		}catch(Exception e){
			log.error("Error processing ExtRAKeyRecoveryRequset : ", e);
			retval = new PKCS12Response(submessage.getRequestId(),false,e.getMessage(),null,null);
		}
		
		return retval;
	}
}

