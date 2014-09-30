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
 
package org.ejbca.externalra.gui;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;
import java.util.Random;

import javax.persistence.Persistence;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.util.CertTools;
import org.cesecore.util.GUIDGenerator;
import org.ejbca.extra.db.CertificateRequestRequest;
import org.ejbca.extra.db.CertificateRequestResponse;
import org.ejbca.extra.db.ExtRAResponse;
import org.ejbca.extra.db.ISubMessage;
import org.ejbca.extra.db.KeyStoreRetrievalRequest;
import org.ejbca.extra.db.KeyStoreRetrievalResponse;
import org.ejbca.extra.db.Message;
import org.ejbca.extra.db.MessageHome;
import org.ejbca.extra.db.SubMessages;
import org.ejbca.extra.util.RAKeyStore;

/**
 * An implementation that uses the External RA API to fetch keystores and certificates from EJBCA.
 * 
 * @version $Id$
 */
public class ExternalRARequestDispatcher implements IRequestDispatcher {

	private static final Logger log = Logger.getLogger(ExternalRARequestDispatcher.class);

	private static X509Certificate extRaCertificate = null;
	private static PrivateKey extRaKey = null;
	private static X509Certificate racaserviceCert = null;
	private static Collection<Certificate> caCerts = null;
    
	private final Random random = new SecureRandom();
	
    public ExternalRARequestDispatcher() {
    	loadKeyStore();
    }
    
    /**
     * Fetch certificates and keys used to protect External RA API messages.
     */
    private static void loadKeyStore() {
        log.trace(">loadKeyStore");
        if (extRaCertificate == null) {
            String extRaKeystorePath = ExternalRaGuiConfiguration.getKeyStorePath();
            String extRaKeystorePwd = ExternalRaGuiConfiguration.getKeyStorePassword();
            if (StringUtils.isEmpty(extRaKeystorePath)) {
                log.error("extRAKeystorePath cannot be empty");
            } else if (StringUtils.isEmpty(extRaKeystorePwd)) {
                log.error("extRAKeystorePath cannot be empty");
            } else {
                try {
                    RAKeyStore extRaKeyStore = new RAKeyStore(extRaKeystorePath, extRaKeystorePwd);
                    extRaCertificate = (X509Certificate)extRaKeyStore.getKeyStore().getCertificate(extRaKeyStore.getAlias());
                    extRaKey = (PrivateKey) extRaKeyStore.getKeyStore().getKey(extRaKeyStore.getAlias(), extRaKeystorePwd.toCharArray());
                    log.info("Loaded keystore from: "+extRaKeystorePath);
                } catch (Exception e) {
                    log.error("Error reading External RA keystore '"+extRaKeystorePath+ " " +extRaKeystorePwd+ "', no keystore loaded: ", e);
                }                             
            }
        }
        if (racaserviceCert == null) {
            String raCaServiceCertPath = ExternalRaGuiConfiguration.getCaServiceCertPath();
            if (StringUtils.isEmpty(raCaServiceCertPath)) {
                log.error("raCaServiceCertPath cannot be empty");
            } else {
                try {
                    Collection<Certificate> coll = CertTools.getCertsFromPEM(raCaServiceCertPath);
                    Iterator<Certificate> i = coll.iterator();
                    if (i.hasNext()) {
                        racaserviceCert = (X509Certificate)i.next();
                        log.info("Loaded certificate from: "+raCaServiceCertPath);
                    } else {
                        log.error("No certificate found in file: "+raCaServiceCertPath);                        
                    }
                } catch (Exception e) {
                    log.error("Error reading RA-CA-service certificate, no certificate loaded: ", e);
                }
            }
        }
        if (caCerts == null) {
        	String filename = ExternalRaGuiConfiguration.getIssuerChainPath();
            try {
				caCerts = CertTools.getCertsFromPEM(filename);
                log.info("Loaded CA certificate chain from: " + filename);
			} catch (CertificateException e) {
				log.error("", e);
				e.printStackTrace();
			} catch (IOException e) {
				log.error("", e);
			}
        }
        log.trace("<loadKeyStore");
    }

	/**
	 * @see org.ejbca.externalra.gui.IRequestDispatcher#getKeyStoreResponse(java.lang.String, java.lang.String)
	 */
	public ResponseInformation getKeyStoreResponse(String username, String password) {
		ResponseInformation keyStoreResponse = null;
		KeyStoreRetrievalResponse responseSub = (KeyStoreRetrievalResponse) getResponseFromCA(new KeyStoreRetrievalRequest(random.nextLong(), username, password));
		if (responseSub != null) {
			if (responseSub.isSuccessful()) {
				keyStoreResponse = new ResponseInformation(responseSub.getKeyStoreData(), responseSub.getKeyStoreType(), null);
			} else {
				keyStoreResponse = new ResponseInformation(null, 0, responseSub.getFailInfo());
			}
		}
		return keyStoreResponse;
	}
	
	/**
	 * @see org.ejbca.externalra.gui.IRequestDispatcher#getCertificateSigningRequestResponse(java.lang.String, java.lang.String, java.lang.String, int)
	 */
	public ResponseInformation getCertificateSigningRequestResponse(String username, String password, String certificateRequest, int responseType) {
		ResponseInformation csrResponse = null;
		CertificateRequestResponse responseSub = (CertificateRequestResponse) getResponseFromCA(new CertificateRequestRequest(
				random.nextLong(), username, password, CertificateRequestRequest.REQUEST_TYPE_PKCS10, certificateRequest.getBytes(), responseType));
		if (responseSub != null) {
			if (responseSub.isSuccessful()) {
				csrResponse = new ResponseInformation(responseSub.getResponseData(), responseSub.getResponseType(), null);
			} else {
				csrResponse = new ResponseInformation(null, 0, responseSub.getFailInfo());
			}
		}
		return csrResponse;
	}
	
	/**
	 * @see org.ejbca.externalra.gui.IRequestDispatcher#getCertificateResponse(java.lang.String, java.lang.String, int, byte[], int)
	 */
	public ResponseInformation getCertificateResponse(String username, String password, int requestType, byte[] buf, int responseType) {
		ResponseInformation certificateResponse = null;
		CertificateRequestResponse responseSub = (CertificateRequestResponse) getResponseFromCA(new CertificateRequestRequest(
				random.nextLong(), username, password, requestType, buf, responseType));
		if (responseSub != null) {
			if (responseSub.isSuccessful()) {
				certificateResponse = new ResponseInformation(responseSub.getResponseData(), responseSub.getResponseType(), null);
			} else {
				certificateResponse = new ResponseInformation(null, 0, responseSub.getFailInfo());
			}
		}
		return certificateResponse;
	}

	/**
	 * Create a new External RA API request message in the database and return the response from the CA.
	 * @return null of the CA did not respond in time
	 */
	private ExtRAResponse getResponseFromCA(ISubMessage subMessage) {
		ExtRAResponse extRAResponse = null;
		// Setup a database interaction and store the request
		MessageHome messageHome = new MessageHome(Persistence.createEntityManagerFactory("ExternalRAGUIMessageDS"), MessageHome.MESSAGETYPE_EXTRA, true);
		SubMessages submessages = new SubMessages(extRaCertificate, extRaKey, racaserviceCert);
		submessages.addSubMessage(subMessage);
		String messageId = GUIDGenerator.generateGUID(this);
		messageHome.create(messageId, submessages);
		// Get response from CA
		Message response = waitForResponse(messageHome, messageId);
		if (response != null) {
			log.debug("Got processed message");
			SubMessages subMessages = response.getSubMessages(extRaKey, caCerts);
			if (subMessages.getSubMessages().size() > 0) {
				log.debug("Got submessage message");
				extRAResponse = (ExtRAResponse) subMessages.getSubMessages().get(0);
			} else {
				log.error("No submessages in External RA API response.");
			}
		}
		return extRAResponse;
	}

	/**
	 * Wait for the CA to write a response to the External RA API database.
	 * @return null if CA did not process request before the timeout.
	 */
	private Message waitForResponse(MessageHome messageHome, String messageId) {
		long startTime = System.currentTimeMillis();
		long timeOut = ExternalRaGuiConfiguration.getTimeOut()*1000L;
		Message response = null;		
		try {
			while (startTime+timeOut>System.currentTimeMillis() && (response==null || !response.getStatus().equals(Message.STATUS_PROCESSED))) {
				Thread.sleep(1000);
				response = messageHome.findByMessageId(messageId);
			}
		} catch (InterruptedException e) {
		}
		if (response == null) {
			log.error("Message has disappeared from database!?!");
		} else if (!response.getStatus().equals(Message.STATUS_PROCESSED)) {
			log.debug("Status of message is " + response.getStatus());
			messageHome.remove(messageId);
			response = null;
		} else {
			messageHome.remove(messageId);
		}
		return response;
	}
}
