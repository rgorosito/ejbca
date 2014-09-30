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

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.util.CertTools;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.approval.ApprovalSessionLocal;
import org.ejbca.core.ejb.authorization.ComplexAccessControlSessionLocal;
import org.ejbca.core.ejb.ca.auth.EndEntityAuthenticationSessionLocal;
import org.ejbca.core.ejb.ca.sign.SignSessionLocal;
import org.ejbca.core.ejb.config.GlobalConfigurationSessionLocal;
import org.ejbca.core.ejb.hardtoken.HardTokenSessionLocal;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySessionLocal;
import org.ejbca.core.ejb.ra.CertificateRequestSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.approvalrequests.AddEndEntityApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.EditEndEntityApprovalRequest;
import org.ejbca.core.model.ra.RAAuthorization;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;
import org.ejbca.extra.caservice.ConfigurationException;
import org.ejbca.extra.db.ExtRARequest;
import org.ejbca.extra.db.ISubMessage;
import org.ejbca.util.query.ApprovalMatch;
import org.ejbca.util.query.BasicMatch;
import org.ejbca.util.query.Query;

/**
 * 
 * @author tomas
 * @version $Id$
 */
public class MessageProcessor {

    private static final Logger log = Logger.getLogger(MessageProcessor.class);

	/** When adding users with approvals, this is a time limit if a user have been rejected, it can not be requested again within this time (minutes) */ 
	private static final int APPROVAL_REJECT_TIMEOUT = -30;

    protected ApprovalSessionLocal approvalSession;
    protected EndEntityAuthenticationSessionLocal authenticationSession;
    protected AccessControlSessionLocal authorizationSession;
    protected ComplexAccessControlSessionLocal complexAccessControlSession;
    protected CaSessionLocal caSession;
    protected CertificateProfileSessionLocal certificateProfileSession;
    protected CertificateStoreSessionLocal certificateStoreSession;
    protected EndEntityAccessSessionLocal endEntityAccessSession;
    protected EndEntityProfileSessionLocal endEntityProfileSession;
    protected HardTokenSessionLocal hardTokenSession;
    protected KeyRecoverySessionLocal keyRecoverySession;
    protected GlobalConfigurationSessionLocal globalConfigurationSession;
    protected SignSessionLocal signSession;
    protected EndEntityManagementSessionLocal endEntityManagementSession;
    protected CertificateRequestSessionLocal certificateRequestSession;
    
    public void setEjbs(Map<Class<?>, Object> ejbs) {
    	approvalSession = (ApprovalSessionLocal) ejbs.get(ApprovalSessionLocal.class);
    	authenticationSession = (EndEntityAuthenticationSessionLocal) ejbs.get(EndEntityAuthenticationSessionLocal.class);
    	authorizationSession = (AccessControlSessionLocal) ejbs.get(AccessControlSessionLocal.class);
    	caSession = (CaSessionLocal) ejbs.get(CaSessionLocal.class);
    	certificateProfileSession = (CertificateProfileSessionLocal) ejbs.get(CertificateProfileSessionLocal.class);
    	certificateStoreSession = (CertificateStoreSessionLocal) ejbs.get(CertificateStoreSessionLocal.class);
    	endEntityProfileSession = (EndEntityProfileSessionLocal) ejbs.get(EndEntityProfileSessionLocal.class);
    	hardTokenSession = (HardTokenSessionLocal) ejbs.get(HardTokenSessionLocal.class);
    	keyRecoverySession = (KeyRecoverySessionLocal) ejbs.get(KeyRecoverySessionLocal.class);
    	globalConfigurationSession = (GlobalConfigurationSessionLocal) ejbs.get(GlobalConfigurationSessionLocal.class);
    	signSession = (SignSessionLocal) ejbs.get(SignSessionLocal.class);
    	endEntityManagementSession = (EndEntityManagementSessionLocal) ejbs.get(EndEntityManagementSessionLocal.class);
    	certificateRequestSession = (CertificateRequestSessionLocal) ejbs.get(CertificateRequestSessionLocal.class);
    	complexAccessControlSession = (ComplexAccessControlSessionLocal)ejbs.get(ComplexAccessControlSessionLocal.class);
    	endEntityAccessSession = (EndEntityAccessSessionLocal) ejbs.get(EndEntityAccessSessionLocal.class);
    }

	/**
	 * Method generating a response to a given sub request, or null of the message should be left in the queue to be tried the next time
	 * 
	 * @param admin the administrator (signer for signed requests, internal user otherwise) performing the action
	 * @param submessage the request submessage
	 * @param errormessage message of an error response to be created
	 * @param ejbs A map between Local EJB interface classes and their injected stub
	 * @return a response, contains failinfo if anything went wrong, or null if the message should not be processed now and should be left in the queue, this can be used to handle approvals.
	 * @throws ConfigurationException 
	 * @throws ClassNotFoundException if the message processor class does not exist in the classpath
	 * @throws IllegalAccessException if the message processor class is invalid
	 * @throws InstantiationException if the message processor class is invalid
	 */
	public static ISubMessage processSubMessage(AuthenticationToken admin, ISubMessage submessage, String errormessage, Map<Class<?>, Object> ejbs) throws ConfigurationException, ClassNotFoundException, InstantiationException, IllegalAccessException {
		ISubMessageProcessor proc = null;
		
		String clazz = submessage.getClass().getName();
		if (log.isDebugEnabled()) {
		    log.debug("Received message of class "+clazz);
		}
		// We can keep the messages and processors in different packages
		if (clazz.startsWith("org.ejbca.extra.db.")) {
			clazz = clazz.replaceFirst("org.ejbca.extra.db.", "org.ejbca.extra.caservice.processor.");
		}
		// Add "Processor", a message processor must always be named MyRequestProcessor, where MyRequest is the classname of the request message
		clazz = clazz + "Processor";
		if (log.isDebugEnabled()) {
		    log.debug("Creating message processor of class "+clazz);
		}
		// Finally create a new message processor using reflection
		@SuppressWarnings("unchecked")
        final Class<? extends ISubMessageProcessor> implClass = (Class<? extends ISubMessageProcessor>) Class.forName(clazz);
		proc = (ISubMessageProcessor)implClass.newInstance();
		proc.setEjbs(ejbs);
		
		ISubMessage ret = proc.process(admin, submessage, errormessage);
		return ret;
	}

	/**
	 * Method returning the CACertChain used to verify the message.
	 * CAChain returned is specified in the service config.
	 * 
	 * @param cAName
	 * @param checkRevokation
	 * @return the CACertChain.
	 * @throws ConfigurationException if any of the CAs doesn't exist or is revoked
	 */
	public static Collection<Certificate> getCACertChain(String cAName, boolean checkRevokation, CaSessionLocal caSession) throws ConfigurationException{		
		try{
		    CAInfo cainfo = caSession.getCAInfoInternal(-1, cAName, true);			
			if(checkRevokation){
			  if(cainfo.getStatus()==CAConstants.CA_REVOKED){
				throw new ConfigurationException("CA " + cainfo.getName() + " Have been revoked");
			  }
			
			  Iterator<Certificate> iter = cainfo.getCertificateChain().iterator();
			  iter.next(); // Throw away the first one.
			  while(iter.hasNext()){
				X509Certificate cacert = (X509Certificate) iter.next();
				CAInfo cainfo2 = caSession.getCAInfoInternal(CertTools.stringToBCDNString(cacert.getSubjectDN().toString()).hashCode(), null, true);
				// This CA may be an external CA, so we don't bother if we can not find it.
				if ((cainfo2 != null) && (cainfo2.getStatus()==CAConstants.CA_REVOKED) ) {
					throw new ConfigurationException("CA " + cainfo2.getName() + " Have been revoked");
				}
			  }
			}  
			return cainfo.getCertificateChain();
        } catch (CADoesntExistsException e) {
            log.error("Misconfigured CA Name in RAService, CA does not exist: "+cAName, e);
            throw new ConfigurationException("Misconfigured CA Name in RAService");
		}catch(Exception e){
			if (e instanceof ConfigurationException) {
				throw (ConfigurationException)e;
			}
			log.error("Exception getting CA cert chain: ", e);
			throw new ConfigurationException("Could not instantiate CAAdminSessionBean");
		}	
	}
	

    protected EndEntityInformation generateEndEntityInformation(AuthenticationToken admin, ExtRARequest submessage) throws ClassCastException, EjbcaException, CADoesntExistsException, AuthorizationDeniedException {
        String dirAttributes = submessage.getSubjectDirectoryAttributes();
        ExtendedInformation ext = null;
        if (dirAttributes != null) {
            ext = new ExtendedInformation();
            ext.setSubjectDirectoryAttributes(dirAttributes);
        }
           return  new EndEntityInformation(submessage.getUsername(),
                   submessage.getSubjectDN(),
                   getCAId(admin,submessage.getCAName()),
                   submessage.getSubjectAltName(),
                   submessage.getEmail(),
                   EndEntityConstants.STATUS_INPROCESS,
                   new EndEntityType(EndEntityTypes.ENDUSER),
                   getEndEntityProfileId(admin, submessage.getEndEntityProfileName()),
                   getCertificateProfileId(submessage.getCertificateProfileName()),
                   null,
                   null,
                   SecConst.TOKEN_SOFT_BROWSERGEN,
                   0,
                   ext);
    }


	/**
	 * Help method used to store userdata in userdatabase with given status, that is
	 * waiting for user to be reviewed. This methid handles approval as well.
	 */
	protected void storeUserData(AuthenticationToken admin, EndEntityInformation userdata, boolean clearpwd, int status) throws Exception {
		log.trace(">storeUserData() username : " + userdata.getUsername());

        // First we will look to see if there is an existing approval request pending for this user within the last hour
		EditEndEntityApprovalRequest ear = new EditEndEntityApprovalRequest(userdata, clearpwd, userdata, admin,null,1,userdata.getCAId(),userdata.getEndEntityProfileId());
        AddEndEntityApprovalRequest aar = new AddEndEntityApprovalRequest(userdata, clearpwd, admin, null, 1, userdata.getCAId(),
                userdata.getEndEntityProfileId());
        int approvalid = aar.generateApprovalId();
		// Check if user already exists
        if (endEntityManagementSession.existsUser(userdata.getUsername())) {
        	// a user already exists, so this is an edit entity request we are preparing
        	log.debug("User already exist, we will look for an edit end entity request");
        	approvalid = ear.generateApprovalId();
        }
		Query query = new Query(Query.TYPE_APPROVALQUERY);		
		query.add(ApprovalMatch.MATCH_WITH_APPROVALID, BasicMatch.MATCH_TYPE_EQUALS, Integer.toString(approvalid), Query.CONNECTOR_AND);
		query.add(ApprovalMatch.MATCH_WITH_STATUS, BasicMatch.MATCH_TYPE_EQUALS, "" + ApprovalDataVO.STATUS_WAITINGFORAPPROVAL, Query.CONNECTOR_AND);
		Date now = new Date();
		Calendar cal = Calendar.getInstance();
		cal.add(Calendar.HOUR_OF_DAY, -1);
		query.add(cal.getTime(), now);
        RAAuthorization raAuthorization = new RAAuthorization(admin, globalConfigurationSession, authorizationSession, complexAccessControlSession, 
                        caSession, endEntityProfileSession);
		List<ApprovalDataVO> approvals = approvalSession.query(admin, query, 0, 25, raAuthorization.getCAAuthorizationString(), raAuthorization.getEndEntityProfileAuthorizationString());
		// If there is an request waiting for approval we don't have to go on and try to add the user
        if (approvals.size() > 0) {
        	log.debug("Found at least one waiting approval request for approvalid: "+approvalid);
        	throw new ApprovalException("There is already an existing approval request pending for approvalid: "+approvalid);
        }
        
		// If there is no waiting request which should be the most common, we check If there is an existing reject withing the last 30 minutes
        // If there is a reject, we will cancel this request. A new request will then probably not be possible to create until 30 minutes have passed
		query = new Query(Query.TYPE_APPROVALQUERY);		
		query.add(ApprovalMatch.MATCH_WITH_APPROVALID, BasicMatch.MATCH_TYPE_EQUALS, Integer.toString(approvalid), Query.CONNECTOR_AND);
		query.add(ApprovalMatch.MATCH_WITH_STATUS, BasicMatch.MATCH_TYPE_EQUALS, "" + ApprovalDataVO.STATUS_EXECUTIONDENIED, Query.CONNECTOR_AND);
		cal = Calendar.getInstance();
		cal.add(Calendar.MINUTE, APPROVAL_REJECT_TIMEOUT);
		query.add(cal.getTime(), now);
		approvals = approvalSession.query(admin, query, 0, 25, raAuthorization.getCAAuthorizationString(), raAuthorization.getEndEntityProfileAuthorizationString());
		// If there is an request waiting for approval we don't have to go on and try to add the user
        if (approvals.size() > 0) {
        	log.debug("Found at least one rejected approval request for approvalid: "+approvalid);
        	throw new Exception("Approval request was rejected for approvalid: "+approvalid);
        }

		// Check if it failed as well...
		query = new Query(Query.TYPE_APPROVALQUERY);		
		query.add(ApprovalMatch.MATCH_WITH_APPROVALID, BasicMatch.MATCH_TYPE_EQUALS, Integer.toString(approvalid), Query.CONNECTOR_AND);
		query.add(ApprovalMatch.MATCH_WITH_STATUS, BasicMatch.MATCH_TYPE_EQUALS, "" + ApprovalDataVO.STATUS_EXECUTIONFAILED, Query.CONNECTOR_AND);
		cal = Calendar.getInstance();
		cal.add(Calendar.MINUTE, -30);
		query.add(cal.getTime(), now);
		approvals = approvalSession.query(admin, query, 0, 25, raAuthorization.getCAAuthorizationString(), raAuthorization.getEndEntityProfileAuthorizationString());
		// If there is an request waiting for approval we don't have to go on and try to add the user
        if (approvals.size() > 0) {
        	log.debug("Found at least one failed approval request for approvalid: "+approvalid);
        	throw new Exception("Approval request execution failed for approvalid: "+approvalid);
        }
        
		// Check if user already exists
		EndEntityInformation oldUserData = endEntityAccessSession.findUser(admin, userdata.getUsername());
		if (oldUserData != null) {
			log.debug("User '"+userdata.getUsername()+"' already exist, edit user.");
			if ( (oldUserData.getStatus() == EndEntityConstants.STATUS_INPROCESS) || (oldUserData.getStatus() == EndEntityConstants.STATUS_NEW) ) {
				log.info("User '"+userdata.getUsername()+"' have status NEW or INPROCESS, we will NOT edit it");
			} else {
				userdata.setStatus(status);
				endEntityManagementSession.changeUser(admin,userdata,clearpwd);			  
			}
		} else {
			log.debug("User '"+userdata.getUsername()+"' does not exist, add user.");
			endEntityManagementSession.addUser(admin,userdata,clearpwd);
			endEntityManagementSession.setUserStatus(admin,userdata.getUsername(), status);
		}
		log.trace("<storeUserData()");
	}

	private int getCertificateProfileId(String certificateProfileName) throws EjbcaException {		
		int retval = certificateProfileSession.getCertificateProfileId(certificateProfileName);
		if(retval == 0){
			throw new EjbcaException("Error Certificate profile '" + certificateProfileName + "' does not exist.");
		}
		return retval;
	}

    private int getEndEntityProfileId(AuthenticationToken admin, String endEntityProfileName) throws EjbcaException {
        try {
            return endEntityProfileSession.getEndEntityProfileId(endEntityProfileName);
        } catch (EndEntityProfileNotFoundException e) {
            throw new EjbcaException("Error End Entity profile '" + endEntityProfileName + "' does not exist.", e);
        }

    }

	private int getCAId(AuthenticationToken admin, String cAName) throws CADoesntExistsException, AuthorizationDeniedException {
		CAInfo info = caSession.getCAInfo(admin,cAName);
		int retval = info.getCAId();
		return retval;
	}
}
