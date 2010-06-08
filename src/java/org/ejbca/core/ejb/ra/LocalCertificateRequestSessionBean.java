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

package org.ejbca.core.ejb.ra;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.ejb.CreateException;
import javax.ejb.EJBException;
import javax.ejb.FinderException;
import javax.ejb.ObjectNotFoundException;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.netscape.NetscapeCertRequest;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.BaseSessionBean;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionLocal;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionLocalHome;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocalHome;
import org.ejbca.core.ejb.ca.sign.ISignSessionLocal;
import org.ejbca.core.ejb.ca.sign.ISignSessionLocalHome;
import org.ejbca.core.ejb.hardtoken.IHardTokenSessionLocal;
import org.ejbca.core.ejb.hardtoken.IHardTokenSessionLocalHome;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocalHome;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.SignRequestSignatureException;
import org.ejbca.core.model.ca.WrongTokenTypeException;
import org.ejbca.core.model.ca.caadmin.CADoesntExistsException;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.core.model.util.GenerateToken;
import org.ejbca.core.protocol.IRequestMessage;
import org.ejbca.core.protocol.IResponseMessage;
import org.ejbca.core.protocol.SimpleRequestMessage;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.RequestMessageUtils;

import com.novosec.pkix.asn1.crmf.CertRequest;

/**
 * Combines EditUser (RA) with CertReq (CA) methods using transactions.
 * Uses JNDI name for datasource as defined in env 'Datasource' in ejb-jar.xml.
 *
 * @version $Id$
 * 
 * @ejb.bean
 *   display-name="CerificateRequestSB"
 *   name="CertificateRequestSession"
 *   jndi-name="CertificateRequestSession"
 *   view-type="both"
 *   type="Stateless"
 *   transaction-type="Container"
 *
 * @ejb.transaction type="Required"
 *
 * @weblogic.enable-call-by-reference True
 *
 * @ejb.env-entry
 *  name="DataSource"
 *  type="java.lang.String"
 *  value="${datasource.jndi-name-prefix}${datasource.jndi-name}"
 *
 * @ejb.home
 *   extends="javax.ejb.EJBHome"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="org.ejbca.core.ejb.ra.ICertificateRequestSessionLocalHome"
 *   remote-class="org.ejbca.core.ejb.ra.ICertificateRequestSessionHome"
 *
 * @ejb.interface
 *   extends="javax.ejb.EJBObject"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="org.ejbca.core.ejb.ra.ICertificateRequestSessionLocal"
 *   remote-class="org.ejbca.core.ejb.ra.ICertificateRequestSessionRemote"
 *   
 * @ejb.ejb-external-ref
 *   description="The User Admin session bean"
 *   view-type="local"
 *   ref-name="ejb/UserAdminSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ra.IUserAdminSessionLocalHome"
 *   business="org.ejbca.core.ejb.ra.IUserAdminSessionLocal"
 *   link="UserAdminSession"
 *
 * @ejb.ejb-external-ref
 *   description="The Authorization session bean"
 *   view-type="local"
 *   ref-name="ejb/AuthorizationSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.authorization.IAuthorizationSessionLocalHome"
 *   business="org.ejbca.core.ejb.authorization.IAuthorizationSessionLocal"
 *   link="AuthorizationSession"
 *
 * @ejb.ejb-external-ref description="The Sign Session Bean"
 *   view-type="local"
 *   ref-name="ejb/RSASignSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ca.sign.ISignSessionLocalHome"
 *   business="org.ejbca.core.ejb.ca.sign.ISignSessionLocal"
 *   link="RSASignSession"
 *
 * @ejb.ejb-external-ref description="The CAAdmin Session Bean"
 *   view-type="local"
 *   ref-name="ejb/CAAdminSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocalHome"
 *   business="org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal"
 *   link="CAAdminSession"
 *
 * @ejb.ejb-external-ref description="The Ra Admin session bean"
 *   view-type="local"
 *   ref-name="ejb/RaAdminSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocalHome"
 *   business="org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocal"
 *   link="RaAdminSession"
 *   
 * @ejb.ejb-external-ref description="The Hard token session bean"
 *   view-type="local"
 *   ref-name="ejb/HardTokenSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.hardtoken.IHardTokenSessionLocalHome"
 *   business="org.ejbca.core.ejb.hardtoken.IHardTokenSessionLocal"
 *   link="HardTokenSession"
 */
public class LocalCertificateRequestSessionBean extends BaseSessionBean {

    /** Requerid method by EJB 2.x. */
    public void ejbCreate() throws CreateException { }

    private IAuthorizationSessionLocal authorizationsession = null;
    private IAuthorizationSessionLocal getAuthorizationSession() {
        if(authorizationsession == null){
          try{
            IAuthorizationSessionLocalHome authorizationsessionhome = (IAuthorizationSessionLocalHome) getLocator().getLocalHome(IAuthorizationSessionLocalHome.COMP_NAME);
            authorizationsession = authorizationsessionhome.create();
          }catch(Exception e){
             throw new EJBException(e);
          }
        }
        return authorizationsession;
    } //getAuthorizationSession

    private IRaAdminSessionLocal raadminsession = null;
    private IRaAdminSessionLocal getRAAdminSession() {
        if(raadminsession == null){
            try{
                IRaAdminSessionLocalHome raadminsessionhome = (IRaAdminSessionLocalHome) getLocator().getLocalHome(IRaAdminSessionLocalHome.COMP_NAME);
                raadminsession = raadminsessionhome.create();
              }catch(Exception e){
                 throw new EJBException(e);
              }
            }
            return raadminsession;
    } //getAuthorizationSession

    private ICAAdminSessionLocal caadminsession = null;
    private ICAAdminSessionLocal getCAAdminSession() {
        if(caadminsession == null){
            try{
                ICAAdminSessionLocalHome caadminsessionhome = (ICAAdminSessionLocalHome) getLocator().getLocalHome(ICAAdminSessionLocalHome.COMP_NAME);
                caadminsession = caadminsessionhome.create();
              }catch(Exception e){
                 throw new EJBException(e);
              }
            }
            return caadminsession;
    } //getAuthorizationSession

    private IUserAdminSessionLocal useradminsession = null;
    private IUserAdminSessionLocal getUserAdminSession() {
        if(useradminsession == null){
            try{
                IUserAdminSessionLocalHome useradminsessionhome = (IUserAdminSessionLocalHome) getLocator().getLocalHome(IUserAdminSessionLocalHome.COMP_NAME);
                useradminsession = useradminsessionhome.create();
              }catch(Exception e){
                 throw new EJBException(e);
              }
            }
            return useradminsession;
    } //getAuthorizationSession

	private ISignSessionLocal signsession = null;
	private ISignSessionLocal getSignSession() {
		if(signsession == null){	  
	      try{
	    	  ISignSessionLocalHome signsessionhome = (ISignSessionLocalHome) getLocator().getLocalHome(ISignSessionLocalHome.COMP_NAME);
	          signsession = signsessionhome.create();
	        }catch(Exception e){
	           throw new EJBException(e);
	        }
	      }
	      return signsession;
	}
 
	private IHardTokenSessionLocal tokensession = null;
	private IHardTokenSessionLocal getHardTokenSession() {
		if(tokensession == null){	  
	      try{
	    	  IHardTokenSessionLocalHome tokensessionhome = (IHardTokenSessionLocalHome) getLocator().getLocalHome(IHardTokenSessionLocalHome.COMP_NAME);
	    	  tokensession = tokensessionhome.create();
	        }catch(Exception e){
	           throw new EJBException(e);
	        }
	      }
	      return tokensession;
	}

	/**
	 * Edits or adds a user and generates a certificate for that user in a single transaction.
     * Used from EjbcaWS.
     * 
	 * @param admin is the requesting administrator
	 * @param userdata contains information about the user that is about to get a certificate
	 * @param req is the certificate request in the format specified in the reqType parameter
	 * @param reqType is one of SecConst.CERT_REQ_TYPE_..
	 * @param hardTokenSN is the hard token to associate this or null
	 * @param responseType is one of SecConst.CERT_RES_TYPE_...
     * @return a encoded certificate of the type specified in responseType 
	 * 
     * @ejb.interface-method
	 */
	public byte[] processCertReq(Admin admin, UserDataVO userdata, String req, int reqType,
			String hardTokenSN, int responseType) throws CADoesntExistsException,
			AuthorizationDeniedException, NotFoundException, InvalidKeyException,
			NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException,
			SignatureException, IOException, ObjectNotFoundException, CreateException,
			CertificateException, UserDoesntFullfillEndEntityProfile,
			ApprovalException, FinderException,
			EjbcaException {
		byte[] retval = null;

		int caid = userdata.getCAId();
		getCAAdminSession().verifyExistenceOfCA(caid);

		String username = userdata.getUsername();
		String password = userdata.getPassword();

		getAuthorizationSession().isAuthorizedNoLog(admin,AccessRulesConstants.CAPREFIX +caid);
		getAuthorizationSession().isAuthorizedNoLog(admin,AccessRulesConstants.REGULAR_CREATECERTIFICATE);
		
		// Check tokentype
		if(userdata.getTokenType() != SecConst.TOKEN_SOFT_BROWSERGEN){
			throw new WrongTokenTypeException ("Error: Wrong Token Type of user, must be 'USERGENERATED' for PKCS10/SPKAC/CRMF/CVC requests");
		}
		// Add or edit user
		try {
			if (getUserAdminSession().findUser(admin, username) != null) {
				log.debug("User " + username + " exists, update the userdata. New status of user '"+userdata.getStatus()+"'." );
				getUserAdminSession().changeUser(admin,userdata, true, true);
			} else {
				log.debug("New User " + username + ", adding userdata. New status of user '"+userdata.getStatus()+"'." );
				getUserAdminSession().addUserFromWS(admin,userdata,true);
			}
		} catch (WaitingForApprovalException e) {
			getSessionContext().setRollbackOnly();	// This is an application exception so it wont trigger a roll-back automatically
			String msg = "Single transaction enrollment request rejected since approvals are enabled for this CA ("+caid+") or Certificate Profile ("+userdata.getCertificateProfileId()+").";
			log.info(msg);
			throw new ApprovalException(msg);
		}
		// Process request
		try {
			IRequestMessage imsg = null;
			if (reqType == SecConst.CERT_REQ_TYPE_PKCS10) {				
				IRequestMessage pkcs10req = RequestMessageUtils.genPKCS10RequestMessage(req.getBytes());
				PublicKey pubKey = pkcs10req.getRequestPublicKey();
				imsg = new SimpleRequestMessage(pubKey, username, password);
			} else if (reqType == SecConst.CERT_REQ_TYPE_SPKAC) {
				// parts copied from request helper.
				byte[] reqBytes = req.getBytes();
				if (reqBytes != null) {
					log.debug("Received NS request: "+new String(reqBytes));
					byte[] buffer = Base64.decode(reqBytes);
					if (buffer == null) {
						return null;
					}
					ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(buffer));
					ASN1Sequence spkacSeq = (ASN1Sequence) in.readObject();
					in.close();
					NetscapeCertRequest nscr = new NetscapeCertRequest(spkacSeq);
					// Verify POPO, we don't care about the challenge, it's not important.
					nscr.setChallenge("challenge");
					if (nscr.verify("challenge") == false) {
						log.debug("POPO verification Failed");
						throw new SignRequestSignatureException("Invalid signature in NetscapeCertRequest, popo-verification failed.");
					}
					log.debug("POPO verification successful");
					PublicKey pubKey = nscr.getPublicKey();
					imsg = new SimpleRequestMessage(pubKey, username, password);
				}		
			} else if (reqType == SecConst.CERT_REQ_TYPE_CRMF) {
				byte[] request = Base64.decode(req.getBytes());
				ASN1InputStream in = new ASN1InputStream(request);
				ASN1Sequence    crmfSeq = (ASN1Sequence) in.readObject();
				ASN1Sequence reqSeq =  (ASN1Sequence) ((ASN1Sequence) crmfSeq.getObjectAt(0)).getObjectAt(0);
				CertRequest certReq = new CertRequest( reqSeq );
				SubjectPublicKeyInfo pKeyInfo = certReq.getCertTemplate().getPublicKey();
				KeyFactory keyFact = KeyFactory.getInstance("RSA", "BC");
				KeySpec keySpec = new X509EncodedKeySpec( pKeyInfo.getEncoded() );
				PublicKey pubKey = keyFact.generatePublic(keySpec); // just check it's ok
				imsg = new SimpleRequestMessage(pubKey, username, password);
				// a simple crmf is not a complete PKI message, as desired by the CrmfRequestMessage class
				//PKIMessage msg = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(request)).readObject());
				//CrmfRequestMessage reqmsg = new CrmfRequestMessage(msg, null, true, null);
				//imsg = reqmsg;
			}
			if (imsg != null) {
				retval = getCertResponseFromPublicKey(admin, imsg, hardTokenSN, responseType);
			}
		} catch (NotFoundException e) {
			getSessionContext().setRollbackOnly();	// This is an application exception so it wont trigger a roll-back automatically
			throw e;
		} catch (InvalidKeyException e) {
			getSessionContext().setRollbackOnly();	// This is an application exception so it wont trigger a roll-back automatically
			throw e;
		} catch (NoSuchAlgorithmException e) {
			getSessionContext().setRollbackOnly();	// This is an application exception so it wont trigger a roll-back automatically
			throw e;
		} catch (InvalidKeySpecException e) {
			getSessionContext().setRollbackOnly();	// This is an application exception so it wont trigger a roll-back automatically
			throw e;
		} catch (NoSuchProviderException e) {
			getSessionContext().setRollbackOnly();	// This is an application exception so it wont trigger a roll-back automatically
			throw e;
		} catch (SignatureException e) {
			getSessionContext().setRollbackOnly();	// This is an application exception so it wont trigger a roll-back automatically
			throw e;
		} catch (IOException e) {
			getSessionContext().setRollbackOnly();	// This is an application exception so it wont trigger a roll-back automatically
			throw e;
		} catch (CertificateException e) {
			getSessionContext().setRollbackOnly();	// This is an application exception so it wont trigger a roll-back automatically
			throw e;
		} catch (EjbcaException e) {
			getSessionContext().setRollbackOnly();	// This is an application exception so it wont trigger a roll-back automatically
			throw e;
		}
		return retval;
	}

	/**
	 * Process a request in the CA module.
	 * 
	 * @param admin is the requesting administrator
	 * @param msg is the request message processed by the CA
	 * @param hardTokenSN is the hard token to associate this or null
	 * @param responseType is one of SecConst.CERT_RES_TYPE_...
     * @return a encoded certificate of the type specified in responseType 
	 */
	private byte[] getCertResponseFromPublicKey(Admin admin, IRequestMessage msg, String hardTokenSN, int responseType)
	throws EjbcaException, CertificateEncodingException, CertificateException, IOException {
		byte[] retval = null;
		Class respClass = org.ejbca.core.protocol.X509ResponseMessage.class; 
		IResponseMessage resp =  getSignSession().createCertificate(admin, msg, respClass);
		java.security.cert.Certificate cert = CertTools.getCertfromByteArray(resp.getResponseMessage());
		if(responseType == SecConst.CERT_RES_TYPE_CERTIFICATE){
			retval = cert.getEncoded();
		}
		if(responseType == SecConst.CERT_RES_TYPE_PKCS7){
			retval = getSignSession().createPKCS7(admin, cert, false);
		}
		if(responseType == SecConst.CERT_RES_TYPE_PKCS7WITHCHAIN){
			retval = getSignSession().createPKCS7(admin, cert, true);
		}

		if(hardTokenSN != null){ 
			getHardTokenSession().addHardTokenCertificateMapping(admin,hardTokenSN,cert);				  
		}
		return retval;
	}

	/**
	 * Edits or adds a user and generates a keystore for that user in a single transaction.
     * Used from EjbcaWS.
     * 
	 * @param admin is the requesting administrator
	 * @param userdata contains information about the user that is about to get a keystore
	 * @param hardTokenSN is the hard token to associate this or null
     * @param keyspec name of ECDSA key or length of RSA and DSA keys  
     * @param keyalg AlgorithmConstants.KEYALGORITHM_RSA, AlgorithmConstants.KEYALGORITHM_DSA or AlgorithmConstants.KEYALGORITHM_ECDSA
     * @param createJKS true to create a JKS, false to create a PKCS12
     * @return an encoded keystore of the type specified in responseType 
     * 
     * @ejb.interface-method
     */
	public byte[] processSoftTokenReq(Admin admin, UserDataVO userdata, String hardTokenSN, String keyspec, String keyalg, boolean createJKS)
	throws CADoesntExistsException, AuthorizationDeniedException, NotFoundException, InvalidKeyException, InvalidKeySpecException, NoSuchProviderException,
	SignatureException, IOException, ObjectNotFoundException, CreateException, CertificateException,UserDoesntFullfillEndEntityProfile,
	ApprovalException, FinderException, EjbcaException, KeyStoreException, NoSuchAlgorithmException,
	InvalidAlgorithmParameterException {
		int caid = userdata.getCAId();
		getCAAdminSession().verifyExistenceOfCA(caid);

		String username = userdata.getUsername();
		String password = userdata.getPassword();

		getAuthorizationSession().isAuthorizedNoLog(admin,AccessRulesConstants.CAPREFIX +caid);
		getAuthorizationSession().isAuthorizedNoLog(admin,AccessRulesConstants.REGULAR_CREATECERTIFICATE);
		try {
			// Add or edit user  
			if (getUserAdminSession().findUser(admin, username) != null) {
				log.debug("User " + username + " exists, update the userdata. New status of user '"+userdata.getStatus()+"'." );
				getUserAdminSession().changeUser(admin,userdata, true, true);
			} else {
				log.debug("New User " + username + ", adding userdata. New status of user '"+userdata.getStatus()+"'." );
				getUserAdminSession().addUserFromWS(admin,userdata,true);
			}
		} catch (WaitingForApprovalException e) {
			getSessionContext().setRollbackOnly();	// This is an application exception so it wont trigger a roll-back automatically
			String msg = "Single transaction keystore request rejected since approvals are enabled for this CA ("+caid+") or Certificate Profile ("+userdata.getCertificateProfileId()+").";
			log.info(msg);
			throw new ApprovalException(msg);
		}
		// Process request
		byte[] ret = null;
		try {
			// Get key recovery info
			boolean usekeyrecovery = getRAAdminSession().loadGlobalConfiguration(admin).getEnableKeyRecovery();
			log.debug("usekeyrecovery: "+usekeyrecovery);
			boolean savekeys = userdata.getKeyRecoverable() && usekeyrecovery &&  (userdata.getStatus() != UserDataConstants.STATUS_KEYRECOVERY);
			log.debug("userdata.getKeyRecoverable(): "+userdata.getKeyRecoverable());
			log.debug("userdata.getStatus(): "+userdata.getStatus());
			log.debug("savekeys: "+savekeys);
			boolean loadkeys = (userdata.getStatus() == UserDataConstants.STATUS_KEYRECOVERY) && usekeyrecovery;
			log.debug("loadkeys: "+loadkeys);
			int endEntityProfileId = userdata.getEndEntityProfileId();
			EndEntityProfile endEntityProfile = getRAAdminSession().getEndEntityProfile(admin, endEntityProfileId);
			boolean reusecertificate = endEntityProfile.getReUseKeyRevoceredCertificate();
			log.debug("reusecertificate: "+reusecertificate);
			// Generate keystore
		    GenerateToken tgen = new GenerateToken(false);
		    KeyStore keyStore = tgen.generateOrKeyRecoverToken(admin, username, password, caid, keyspec, keyalg, createJKS, loadkeys, savekeys, reusecertificate, endEntityProfileId);
			String alias = keyStore.aliases().nextElement();
		    X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
		    if ( (hardTokenSN != null) && (cert != null) ) {
		    	getHardTokenSession().addHardTokenCertificateMapping(admin,hardTokenSN,cert);                 
		    }
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			keyStore.store(baos, password.toCharArray());
			ret = baos.toByteArray();
		} catch (NotFoundException e) {
			getSessionContext().setRollbackOnly();	// This is an application exception so it wont trigger a roll-back automatically
			throw e;
		} catch (InvalidKeyException e) {
			getSessionContext().setRollbackOnly();	// This is an application exception so it wont trigger a roll-back automatically
			throw e;
		} catch (NoSuchAlgorithmException e) {
			getSessionContext().setRollbackOnly();	// This is an application exception so it wont trigger a roll-back automatically
			throw e;
		} catch (InvalidKeySpecException e) {
			getSessionContext().setRollbackOnly();	// This is an application exception so it wont trigger a roll-back automatically
			throw e;
		} catch (NoSuchProviderException e) {
			getSessionContext().setRollbackOnly();	// This is an application exception so it wont trigger a roll-back automatically
			throw e;
		} catch (SignatureException e) {
			getSessionContext().setRollbackOnly();	// This is an application exception so it wont trigger a roll-back automatically
			throw e;
		} catch (IOException e) {
			getSessionContext().setRollbackOnly();	// This is an application exception so it wont trigger a roll-back automatically
			throw e;
		} catch (CertificateException e) {
			getSessionContext().setRollbackOnly();	// This is an application exception so it wont trigger a roll-back automatically
			throw e;
		} catch (EjbcaException e) {
			getSessionContext().setRollbackOnly();	// This is an application exception so it wont trigger a roll-back automatically
			throw e;
		} catch (InvalidAlgorithmParameterException e) {
			getSessionContext().setRollbackOnly();	// This is an application exception so it wont trigger a roll-back automatically
			throw e;
		} catch (RuntimeException e) {
			throw e;
		} catch (Exception e) {
			getSessionContext().setRollbackOnly();	// This is an application exception so it wont trigger a roll-back automatically
			throw new KeyStoreException(e);
		}
	    return ret;
	}
}
