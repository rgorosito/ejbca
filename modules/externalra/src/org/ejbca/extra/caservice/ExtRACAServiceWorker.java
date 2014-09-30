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
package org.ejbca.extra.caservice;

import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import javax.persistence.EntityManagerFactory;
import javax.persistence.Persistence;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.ejbca.core.ejb.authentication.web.WebAuthenticationProviderSessionLocal;
import org.ejbca.core.model.services.BaseWorker;
import org.ejbca.core.model.services.ServiceExecutionFailedException;
import org.ejbca.extra.caservice.processor.MessageProcessor;
import org.ejbca.extra.db.ISubMessage;
import org.ejbca.extra.db.Message;
import org.ejbca.extra.db.MessageHome;
import org.ejbca.extra.db.SubMessages;
import org.ejbca.extra.util.RAKeyStore;

/** An EJBCA Service worker that polls the External RA database for extRA messages and processes them.
 * The design includes that no two workers with the same serviceName can run on the same CA host at the same time.
 * 
 * @version $Id$
 */
public class ExtRACAServiceWorker extends BaseWorker {

	private static Logger log = Logger.getLogger(ExtRACAServiceWorker.class);

	private boolean encryptionRequired = false;
	private boolean signatureRequired = false;
	private String keystorePwd = null;
	private String caname = null;
	private String whiteList = null;
	
	private static ConcurrentHashMap<String, EntityManagerFactory> entityManagerFactories = new ConcurrentHashMap<String, EntityManagerFactory>();
    
	private MessageHome msgHome = null;
	
	private RAKeyStore serviceKeyStore = null;

	//private Admin internalUser = Admin.getInternalAdmin();
	private AuthenticationToken internalUser = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("ExtRACAServiceWorker"));
	
	/** Semaphore to keep several processes from running simultaneously on the same host */
	private static HashMap<String,Object> running = new HashMap<String,Object>();

	private CaSessionLocal caSession;
    private WebAuthenticationProviderSessionLocal authenticationSession;
	
	/**
	 * Checks if there are any new messages on the External RA and processes them.
	 * 
	 * @see org.ejbca.core.model.services.IWorker#work(Map<Class<?>, Object>)
	 */
	public void work(Map<Class<?>, Object> ejbs) throws ServiceExecutionFailedException {
		if (log.isDebugEnabled()) {
			log.debug(">work: "+serviceName);
		}
        caSession = (CaSessionLocal)ejbs.get(CaSessionLocal.class);
        authenticationSession = (WebAuthenticationProviderSessionLocal)ejbs.get(WebAuthenticationProviderSessionLocal.class);
		if (startWorking()) {
			try {
				// A semaphore used to not run parallel service jobs on the same host so not to start unlimited number of threads just
				// because there is a lot of work to do.
				init();
				processWaitingMessages(ejbs);
			} finally {
				stopWorking();
			}			
		} else {
			log.info("Service "+ExtRACAServiceWorker.class.getName()+" with name "+serviceName+" is already running in this VM! Not starting work.");
		}
		if (log.isDebugEnabled()) {
			log.debug("<work: "+serviceName);
		}
	}

	/** Synchronized method that makes checks if another service thread with this particular service name is already running. 
	 * If another service thread is running, false is returned. If another service is not running true is returned and an object is inserted in the running HashMap
	 * to indicate that this service thread is running. 
	 * @return false is another service thread with the same serviceName is running, false otherwise.
	 */
	private synchronized boolean startWorking() {
		boolean ret = false;
		Object o = running.get(serviceName);
		if (o == null) {
			running.put(serviceName, new Object());
			ret = true;
		} 
		return ret;
	}
	/** Removes the object, that was inserted in startWorking() from the running HashMap.
	 * @see #startWorking 
	 */
	private synchronized void stopWorking() {
		running.remove(serviceName);
	}
	
	private void init() {

		// Read configuration properties
		// First we get it from the built in configuration in the properties file using ConfigurationHolder
		// Second we try to override this value with a value from the properties of this specific worker, configured in the GUI
		// Oh, and if no configuration exist it uses the hard coded values from the top of this file.
		
		String persistenceUnit = this.properties.getProperty("externalra-caservice.persistenceunit", "RAMessage1DS").trim();
		if (log.isDebugEnabled()) {
			log.debug("externalra-caservice.hibernateresource: " + persistenceUnit);
		}
		String keystorePath = this.properties.getProperty("externalra-caservice.keystore.path", "keystore/extrakeystore.p12").trim();
		if (log.isDebugEnabled()) {
			log.debug("externalra-caservice.keystore.path: "+keystorePath);
		}
		keystorePwd = this.properties.getProperty("externalra-caservice.keystore.pwd", "foo123").trim();
		if (log.isDebugEnabled()) {
			log.debug("externalra-caservice.keystore.pwd: "+keystorePwd);
		}
		// Always fallback to safe value (true) if we enter something stupid
		encryptionRequired = !"false".equals(this.properties.getProperty("externalra-caservice.encryption.required", "false").trim());
		if (log.isDebugEnabled()) {
			log.debug("externalra-caservice.encryption.required: "+encryptionRequired);
		}
		signatureRequired = !"false".equals(this.properties.getProperty("externalra-caservice.signature.required", "false").trim());
		if (log.isDebugEnabled()) {
			log.debug("externalra-caservice.signature.required: "+signatureRequired);
		}
		caname = this.properties.getProperty("externalra-caservice.raissuer", "ManagementCA").trim();
		if (log.isDebugEnabled()) {
			log.debug("externalra-caservice.raissuer: "+caname);
		}		
		whiteList = this.properties.getProperty("externalra-caservice.whitelist", "").trim();
		if (log.isDebugEnabled()) {
			log.debug("externalra-caservice.whitelist: "+whiteList);
		}		
		// Initialize the JPA provider with the current persistence unit
		if (entityManagerFactories.get(persistenceUnit) == null) {
			EntityManagerFactory entityManagerFactory = Persistence.createEntityManagerFactory(persistenceUnit);
			EntityManagerFactory entityManagerFactoryOld = entityManagerFactories.putIfAbsent(persistenceUnit, entityManagerFactory);
			if (entityManagerFactoryOld!=null && !entityManagerFactoryOld.equals(entityManagerFactory)) {
				entityManagerFactory.close();
			} else {
				log.info("Created new entity manager factory for persistence unit '" + persistenceUnit + "'");
			}
		}
        msgHome = new MessageHome(entityManagerFactories.get(persistenceUnit), MessageHome.MESSAGETYPE_EXTRA, true);	// We manage transactions ourself for this DataSource

		try {
			serviceKeyStore = new RAKeyStore(keystorePath, keystorePwd);
		} catch (Exception e) {
			if(encryptionRequired || signatureRequired){
			  log.error("Error reading ExtRACAService keystore" ,e);
			}else{
				if (log.isDebugEnabled()) {
					log.debug("ExtRACAService KeyStore couldn't be configured, but isn't required");
				}
			}
		}
	}

	/**
	 * Loops and gets waiting messages from the extRA database as long as there are any, and processes them. 
	 * If there are no more messages in status waiting the method ends.
	 * @param ejbs A map between Local EJB interface classes and their injected stub
	 */
	public void processWaitingMessages(Map<Class<?>, Object> ejbs) {

	    // Check if caname exists
	    final boolean exists = caSession.existsCa(caname);
		if (!exists) {
			if(encryptionRequired || signatureRequired){
				log.error("RAIssuer is misconfigured, and is required. CA does not exist: "+caname);
				return;
			}else{
				if (log.isDebugEnabled()) {
					log.debug("RAIssuer is misconfigured, but isn't required. CA does not exist: "+caname);
				}
			}
		}				

		Message msg = null;
		String lastMessageId = null;
		do{	
			msg = msgHome.getNextWaitingMessage();
			// A small section that makes sure we don't loop too quickly over the same message.
			// Check if we are trying to process the same messageId as the last time. If this is the case exit from the loop and let the next 
			// worker try to process it.
			// If it is not the same messageId process the message immediately.
			if (msg != null) {
				String id = msg.getMessageid();
				if (StringUtils.equals(id, lastMessageId)) {
					log.info("The same message (" + id + ") was in the queue twice, putting back and exiting from the current loop");
					// Re-set status to waiting so we will process it the next time the service is run
					msg.setStatus(Message.STATUS_WAITING);
					msgHome.update(msg);							
					msg = null;
				} else {
					String errormessage = null;
					SubMessages submgs = null;
					try {
						log.info("Started processing message with messageId: " + msg.getMessageid()+", and uniqueId: "+msg.getUniqueId()); 

						if (serviceKeyStore != null) {
					        final Collection<Certificate> cACertChain = MessageProcessor.getCACertChain(caname, true, caSession);
							submgs = msg.getSubMessages(
									(PrivateKey) serviceKeyStore.getKeyStore().getKey(serviceKeyStore.getAlias(), keystorePwd.toCharArray()),
									cACertChain);
						} else {
							submgs =  msg.getSubMessages(null,null);
						}
						if (log.isDebugEnabled()) {
							if (submgs.isSigned()) {
								log.debug("Message from : " + msg.getMessageid() + " was signed");
							}
							if (submgs.isEncrypted()) {
								log.debug("Message from : " + msg.getMessageid() + " was encrypted");
							}
						}
						if (signatureRequired && !submgs.isSigned()) {
							errormessage = "Error: Message from : " + msg.getMessageid() + " wasn't signed which is a requirement";
							log.error(errormessage);

						}
						if (encryptionRequired && !submgs.isEncrypted()) {
							errormessage = "Error: Message from : " + msg.getMessageid() + " wasn't encrypted which is a requirement";
							log.error(errormessage);
						}
					} catch (Exception e) {
						errormessage = "Error processing waiting message with Messageid : " + msg.getMessageid() + " : "+ e.getMessage();
						log.error("Error processing waiting message with Messageid : " + msg.getMessageid(), e);
					}

					if (submgs != null) {
						SubMessages respSubMsg;
						try {
							respSubMsg = generateResponseSubMessage(submgs.getSignerCert());
							Iterator<ISubMessage> iter = submgs.getSubMessages().iterator();
							boolean somethingprocessed = false;
							while(iter.hasNext()){
								ISubMessage reqMsg = iter.next();
								if (!checkWhiteList(reqMsg)) {
									errormessage = "Sub message of type " + reqMsg.getClass().getName() + " is not listed in white list. Message id: " + msg.getMessageid();
								}
								ISubMessage respMsg = MessageProcessor.processSubMessage(getAdmin(submgs), reqMsg, errormessage, ejbs);
								if (respMsg != null) {
									// if the response message is null here, we will ignore this message, 
									// it means that we should not do anything with it this round 
									respSubMsg.addSubMessage(respMsg);
									somethingprocessed = true;
								}
							}
							if (somethingprocessed) {
								msg.setStatus(Message.STATUS_PROCESSED);
								msg.setSubMessages(respSubMsg);
							} else {
								log.info("Nothing processed for msg with messageId: "+msg.getMessageid()+", leaving it in the queue");
								msg.setStatus(Message.STATUS_WAITING);
								// Update create time, so that we will process the next message instead of this again the next round in the loop
								msg.setCreatetime((new Date()).getTime());
							}
							msgHome.update(msg);							
						} catch (Exception e) {
							log.error("Error generating response message with Messageid : " + msg.getMessageid(), e);
						}

					}					
				}
				lastMessageId = id;	    	 
			}
		} while (msg != null);

	} // processWaitingMessage
	
	
	protected MessageHome getMessageHome() {
		return msgHome;
	}

	protected void storeMessageInRA(Message msg){
		if (log.isTraceEnabled()) {
			log.trace(">storeMessageInRA() MessageId : " + msg.getMessageid());
		}
		getMessageHome().update(msg);
		if (log.isTraceEnabled()) {
			log.trace("<storeMessageInRA() MessageId : " + msg.getMessageid());
		}
	}
	

	// 
	// Private helper methods
	//
	
	/**
	 * Method used to retrieve which administrator to use.
	 * If message is signed then use the signer as admin otherwise use InternalUser
	 * @throws SignatureException 
	 * @throws AuthorizationDeniedException 
	 */
	private AuthenticationToken getAdmin(SubMessages submessages) throws SignatureException, AuthorizationDeniedException{
		if(submessages.isSigned()){
			// Check if Signer Cert is revoked
			X509Certificate signerCert = submessages.getSignerCert();
			
	        final Set<X509Certificate> credentials = new HashSet<X509Certificate>();
	        credentials.add(signerCert);
	        AuthenticationSubject subject = new AuthenticationSubject(null, credentials);
	        AuthenticationToken admin = authenticationSession.authenticate(subject);
	        if (admin == null) {
				throw new SignatureException("Error Signer certificate does not exist or is revoked.");
	        }
			return admin;
		}
		return internalUser;
	}	
	
	/**
	 * Method that generates a response submessage depending on
	 * required security configuration
	 * @param reqCert the requestors certificate used for encryption.
	 * @return a new instance of a SubMessage
	 * @throws UnrecoverableKeyException 
	 * @throws NoSuchAlgorithmException 
	 * @throws KeyStoreException 
	 */	
	private SubMessages generateResponseSubMessage(X509Certificate reqCert) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
		
		if(encryptionRequired && signatureRequired){
			return new SubMessages((X509Certificate) serviceKeyStore.getKeyStore().getCertificate(serviceKeyStore.getAlias()),
					               (PrivateKey) serviceKeyStore.getKeyStore().getKey(serviceKeyStore.getAlias(), keystorePwd.toCharArray()),
					               reqCert);					                
		}
		if(signatureRequired){
			return new SubMessages((X509Certificate) serviceKeyStore.getKeyStore().getCertificate(serviceKeyStore.getAlias()),
					               (PrivateKey) serviceKeyStore.getKeyStore().getKey(serviceKeyStore.getAlias(), keystorePwd.toCharArray()),
					               null);					                
		}
		if(encryptionRequired){
			return new SubMessages(null,
					               null,
					               reqCert);					                
		}
		
		return new SubMessages(null,null,null);
	}

	/**
	 * Check if the classname is listed in the whitelist of allowed classes.
	 * @param reqMsg is request submessage
	 * @return true if the classname was found in the whitelist or if the whitelist is empty
	 */
	private boolean checkWhiteList(ISubMessage reqMsg) {
		String classname = reqMsg.getClass().getName();
		if (whiteList == null || whiteList.length() == 0) {
			return true;
		}
		if (whiteList.indexOf(classname) == -1) {
			log.info("Rejected External RA API submessage of type " + classname + " since it's not in the whitelist.");
			if (log.isDebugEnabled()) {
				log.debug("Whitelist was " + whiteList);
			}
			return false;
		}
		return true;
	}

}
