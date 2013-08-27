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

import java.io.ByteArrayOutputStream;
import java.security.KeyStore;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.ejbca.config.Configuration;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.util.GenerateToken;
import org.ejbca.extra.db.ExtRARequest;
import org.ejbca.extra.db.ISubMessage;
import org.ejbca.extra.db.KeyStoreRetrievalRequest;
import org.ejbca.extra.db.KeyStoreRetrievalResponse;

/**
 * Process keystore generation/retrieval requests.
 * 
 * @version $Id$
 */
public class KeyStoreRetrievalRequestProcessor extends MessageProcessor implements ISubMessageProcessor {

	private static final Logger log = Logger.getLogger(KeyStoreRetrievalRequestProcessor.class);

	/** @see ISubMessageProcessor#process(AuthenticationToken, ISubMessage, String) */
	public ISubMessage process(AuthenticationToken admin, ISubMessage submessage, String errormessage) {
		if(errormessage == null){
			return processKeyStoreRetrievalRequest(admin, (KeyStoreRetrievalRequest) submessage);
		}else{
			return new KeyStoreRetrievalResponse(((ExtRARequest) submessage).getRequestId(), false, errormessage, null, null);
		}
	}

    /**
     * Lookup the requested user and generate or recover a keystore.
     */
    private KeyStoreRetrievalResponse processKeyStoreRetrievalRequest(AuthenticationToken admin, KeyStoreRetrievalRequest submessage) {
        log.debug("Processing KeyStoreRetrievalRequest");
		try {
			EndEntityInformation data = null;
			try {
				data = endEntityAccessSession.findUser(admin, submessage.getUsername());
			} catch (AuthorizationDeniedException e) {
				log.info("External RA admin was denied access to a user: " + e.getMessage());
			}
			if (data == null) {
				return new KeyStoreRetrievalResponse(((ExtRARequest) submessage).getRequestId(), false, "No such user.", null, null);
			}
			// Find out if are doing key recovery
			int endEntityProfileId = data.getEndEntityProfileId();	// TODO should probably also be used to get keysize and algorithm in the future..
			boolean usekeyrecovery = ((GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(Configuration.GlobalConfigID)).getEnableKeyRecovery();
			boolean savekeys = data.getKeyRecoverable() && usekeyrecovery &&  (data.getStatus() != EndEntityConstants.STATUS_KEYRECOVERY);
			boolean loadkeys = (data.getStatus() == EndEntityConstants.STATUS_KEYRECOVERY) && usekeyrecovery;
			boolean reusecertificate = endEntityProfileSession.getEndEntityProfile(endEntityProfileId).getReUseKeyRecoveredCertificate();
			// Generate or recover keystore and save it in the configured format 
			GenerateToken tgen = new GenerateToken(authenticationSession, endEntityAccessSession, endEntityManagementSession, caSession, keyRecoverySession, signSession);
			byte[] buf = null;
			int tokentype = data.getTokenType();
			boolean createJKS = (tokentype == SecConst.TOKEN_SOFT_JKS);
			KeyStore ks = tgen.generateOrKeyRecoverToken(admin, submessage.getUsername(), submessage.getPassword(), data.getCAId(), "2048", AlgorithmConstants.KEYALGORITHM_RSA,
					createJKS, loadkeys, savekeys, reusecertificate, endEntityProfileId);
			if (tokentype == SecConst.TOKEN_SOFT_PEM) {
				buf = KeyTools.getSinglePemFromKeyStore(ks, submessage.getPassword().toCharArray());
			} else if (tokentype == SecConst.TOKEN_SOFT_P12 || tokentype == SecConst.TOKEN_SOFT_JKS) {
				ByteArrayOutputStream baos = new ByteArrayOutputStream();
				ks.store(baos, submessage.getPassword().toCharArray());
				buf = baos.toByteArray();
			} else {
				return new KeyStoreRetrievalResponse(submessage.getRequestId(), false, "Unknown token type.", null, null);
			}
			return new KeyStoreRetrievalResponse(submessage.getRequestId(), true, null, tokentype, buf);
		} catch (Exception e) {
			log.debug("External RA request generated an error: " + e.getMessage());
			return new KeyStoreRetrievalResponse(submessage.getRequestId(), false, "Error " + e.getMessage(), null, null);
		}
	}
}
