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

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

import javax.ejb.ObjectNotFoundException;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ca.sign.ISignSessionLocal;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.ca.IllegalKeyException;
import org.ejbca.core.model.ca.SignRequestException;
import org.ejbca.core.model.ca.SignRequestSignatureException;
import org.ejbca.core.model.ca.caadmin.CADoesntExistsException;
import org.ejbca.core.model.ca.store.CertificateInfo;
import org.ejbca.core.model.hardtoken.profiles.EIDProfile;
import org.ejbca.core.model.hardtoken.profiles.HardTokenProfile;
import org.ejbca.core.model.hardtoken.profiles.SwedishEIDProfile;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.protocol.IResponseMessage;
import org.ejbca.core.protocol.PKCS10RequestMessage;
import org.ejbca.core.protocol.X509ResponseMessage;
import org.ejbca.extra.db.CardRenewalRequest;
import org.ejbca.extra.db.CardRenewalResponse;
import org.ejbca.extra.db.ExtRARequest;
import org.ejbca.extra.db.ExtRAResponse;
import org.ejbca.extra.db.ISubMessage;
import org.ejbca.util.CertTools;
import org.ejbca.util.RequestMessageUtils;

/**
 * 
 * @author tomas
 * @version $Id$
 */
public class CardRenewalRequestProcessor extends MessageProcessor implements ISubMessageProcessor {
    private static final Logger log = Logger.getLogger(CardRenewalRequestProcessor.class);

    public ISubMessage process(Admin admin, ISubMessage submessage, String errormessage) {
		if(errormessage == null){
			return processExtRACardRenewalRequest(admin, (CardRenewalRequest) submessage);
		}else{
			return new ExtRAResponse(((ExtRARequest) submessage).getRequestId(), false, errormessage);
		}
    }

    private ISubMessage processExtRACardRenewalRequest(Admin admin, CardRenewalRequest submessage) {
		log.debug("Processing ExtRACardRenewalRequest");
		ExtRAResponse retval = null;
		try {
			Certificate authcert = submessage.getAuthCertificate();
			Certificate signcert = submessage.getSignCertificate();
			String authReq = submessage.getAuthPkcs10();
			String signReq = submessage.getSignPkcs10();
			if ( (authcert == null) || (signcert == null) || (authReq == null) || (signReq == null) ) {
				retval = new ExtRAResponse(submessage.getRequestId(),false,"An authentication cert, a signature cert, an authentication request and a signature request are required");
			} else {
				BigInteger serno = CertTools.getSerialNumber(authcert);
				String issuerDN = CertTools.getIssuerDN(authcert);
                // Verify the certificates with CA cert, and then verify the pcks10 requests
                CertificateInfo authInfo = ejb.getCertStoreSession().getCertificateInfo(admin, CertTools.getFingerprintAsString(authcert));
                Certificate authcacert = ejb.getCertStoreSession().findCertificateByFingerprint(admin, authInfo.getCAFingerprint());
                CertificateInfo signInfo = ejb.getCertStoreSession().getCertificateInfo(admin, CertTools.getFingerprintAsString(signcert));
                Certificate signcacert = ejb.getCertStoreSession().findCertificateByFingerprint(admin, signInfo.getCAFingerprint());
                // Verify certificate
                try {
                    authcert.verify(authcacert.getPublicKey());                    
                } catch (Exception e) {
                    log.error("Error verifying authentication certificate: ", e);
                    retval = new ExtRAResponse(submessage.getRequestId(),false,"Error verifying authentication certificate: "+e.getMessage());
                    return retval;
                }
                try {
                    signcert.verify(signcacert.getPublicKey());                    
                } catch (Exception e) {
                    log.error("Error verifying signature certificate: ", e);
                    retval = new ExtRAResponse(submessage.getRequestId(),false,"Error verifying signature certificate: "+e.getMessage());
                    return retval;
                }
                // Verify requests
                byte[] authReqBytes = authReq.getBytes();
                byte[] signReqBytes = signReq.getBytes();
                PKCS10RequestMessage authPkcs10 = RequestMessageUtils.genPKCS10RequestMessage(authReqBytes);
                PKCS10RequestMessage signPkcs10 = RequestMessageUtils.genPKCS10RequestMessage(signReqBytes);
                String authok = null;
                try {
                    if (!authPkcs10.verify(authcert.getPublicKey())) {
                        authok = "Verify failed for authentication request";
                    }                    
                } catch (Exception e) {
                    authok="Error verifying authentication request: "+e.getMessage();
                    log.error("Error verifying authentication request: ", e);
                }
                if (authok != null) {
                    retval = new ExtRAResponse(submessage.getRequestId(),false,authok);
                    return retval;                                        
                }
                String signok = null;
                try {
                    if (!signPkcs10.verify(signcert.getPublicKey())) {
                        signok = "Verify failed for signature request";
                    }                    
                } catch (Exception e) {
                    signok="Error verifying signaturerequest: "+e.getMessage();
                    log.error("Error verifying signaturerequest: ", e);
                }
                if (signok != null) {
                    retval = new ExtRAResponse(submessage.getRequestId(),false,signok);
                    return retval;                                        
                }
                
                // Now start the actual work, we are ok and verified here
				String username = ejb.getCertStoreSession().findUsernameByCertSerno(admin, serno, CertTools.stringToBCDNString(issuerDN));
				if (username != null) {
		            final UserDataVO data = ejb.getUserAdminSession().findUser(admin, username);
		            if ( data.getStatus() != UserDataConstants.STATUS_NEW) {
		            	log.error("User status must be new for "+username);
						retval = new ExtRAResponse(submessage.getRequestId(),false,"User status must be new for "+username);
		            } else {
                        log.info("Processing Card Renewal for: issuer='"+issuerDN+"', serno="+serno);
                        int authCertProfile = -1;
                        int signCertProfile = -1;
                        int authCA = -1;
                        int signCA = -1;
                        // Get the profiles and CAs from the message if they exist
		            	if (submessage.getAuthProfile() != -1) {
		            		authCertProfile = submessage.getAuthProfile();
		            	}
		            	if (submessage.getSignProfile() != -1) {
		            		signCertProfile = submessage.getSignProfile();
		            	}
		            	if (submessage.getAuthCA() != -1) {
		            		authCA = submessage.getAuthCA();
		            	}
		            	if (submessage.getSignCA() != -1) {
		            		signCA = submessage.getSignCA();
		            	}
                        HardTokenProfile htp = ejb.getHardTokenSession().getHardTokenProfile(admin, data.getTokenType());
                        if ( htp!=null && htp instanceof EIDProfile ) {
                        	EIDProfile hardTokenProfile = (EIDProfile)htp;
                        	if (authCertProfile == -1) {
                        		authCertProfile = hardTokenProfile.getCertificateProfileId(SwedishEIDProfile.CERTUSAGE_AUTHENC);                        		
                        	}
                        	if (signCertProfile == -1) {
                        		signCertProfile = hardTokenProfile.getCertificateProfileId(SwedishEIDProfile.CERTUSAGE_SIGN);
                        	}
                        	if (authCA == -1) {
                        		authCA = hardTokenProfile.getCAId(SwedishEIDProfile.CERTUSAGE_AUTHENC);
                        		if (authCA == EIDProfile.CAID_USEUSERDEFINED) {
                        			authCA = data.getCAId();
                        		}
                        	}
                        	if (signCA == -1) {
                        		signCA = hardTokenProfile.getCAId(SwedishEIDProfile.CERTUSAGE_SIGN);
                        		if (signCA == EIDProfile.CAID_USEUSERDEFINED) {
                        			signCA = data.getCAId();
                        		}                        		
                        	}
                        } else {
                        	if (authCertProfile == -1) {
                        		authCertProfile = data.getCertificateProfileId();
                        	}
                        	if (signCertProfile == -1) {
                        		signCertProfile = data.getCertificateProfileId();
                        	}
                        	if (authCA == -1) {
                        		authCA = data.getCAId();
                        	}
                        	if (signCA == -1) {
                        		signCA = data.getCAId();
                        	}
                        }

		            	// Set certificate profile and CA for auth certificate
                        UserDataVO newUser = new UserDataVO(username, data.getDN(), authCA, data.getSubjectAltName(), data.getEmail(), data.getType(), data.getEndEntityProfileId(), authCertProfile, data.getTokenType(), data.getHardTokenIssuerId(), null);
                        newUser.setPassword(data.getPassword());
                        ejb.getUserAdminSession().setUserStatus(admin, username, UserDataConstants.STATUS_NEW);
                        ejb.getUserAdminSession().changeUser(admin, newUser, false); 

		            	// We may have changed to a new auto generated password
			            UserDataVO data1 = ejb.getUserAdminSession().findUser(admin, username);
		            	Certificate authcertOut=pkcs10CertRequest(admin, ejb.getSignSession(), authPkcs10, username, data1.getPassword());

		            	// Set certificate and CA for sign certificate
                        newUser = new UserDataVO(username, data.getDN(), signCA, data.getSubjectAltName(), data.getEmail(), data.getType(), data.getEndEntityProfileId(), signCertProfile, data.getTokenType(), data.getHardTokenIssuerId(), null);
                        newUser.setPassword(data.getPassword());
                        ejb.getUserAdminSession().setUserStatus(admin, username, UserDataConstants.STATUS_NEW);
                        ejb.getUserAdminSession().changeUser(admin, newUser, false); 

                        // We may have changed to a new auto generated password
			            data1 = ejb.getUserAdminSession().findUser(admin, username);
		            	Certificate signcertOut=pkcs10CertRequest(admin, ejb.getSignSession(), signPkcs10, username, data1.getPassword());

		            	// We are generated all right
		            	data.setStatus(UserDataConstants.STATUS_GENERATED);
		            	// set back to original values (except for generated)
		            	ejb.getUserAdminSession().changeUser(admin, data, true); 
		            	retval = new CardRenewalResponse(submessage.getRequestId(), true, null, authcertOut, signcertOut);
		            }
				} else {
                    log.error("User not found from issuer/serno: issuer='"+issuerDN+"', serno="+serno);
					retval = new ExtRAResponse(submessage.getRequestId(),false,"User not found from issuer/serno: issuer='"+issuerDN+"', serno="+serno);					
				}
			} 			
		} catch(Exception e) {
			log.error("Error processing ExtRACardRenewalRequest : ", e);
			retval = new ExtRAResponse(submessage.getRequestId(),false,e.getMessage());
		} 
			
		return retval;
	}

    /**
     * Handles PKCS10 certificate request, these are constructed as: <code> CertificationRequest
     * ::= SEQUENCE { certificationRequestInfo  CertificationRequestInfo, signatureAlgorithm
     * AlgorithmIdentifier{{ SignatureAlgorithms }}, signature                       BIT STRING }
     * CertificationRequestInfo ::= SEQUENCE { version             INTEGER { v1(0) } (v1,...),
     * subject             Name, subjectPKInfo   SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
     * attributes          [0] Attributes{{ CRIAttributes }}} SubjectPublicKeyInfo { ALGORITHM :
     * IOSet} ::= SEQUENCE { algorithm           AlgorithmIdentifier {{IOSet}}, subjectPublicKey
     * BIT STRING }</code> PublicKey's encoded-format has to be RSA X.509.
     *
     * @param signsession signsession to get certificate from
     * @param b64Encoded base64 encoded pkcs10 request message
     * @param username username of requesting user
     * @param password password of requesting user
     * @param resulttype should indicate if a PKCS7 or just the certificate is wanted.
     *
     * @return Base64 encoded byte[] 
     * @throws ClassNotFoundException 
     * @throws SignRequestSignatureException 
     * @throws SignRequestException 
     * @throws CADoesntExistsException 
     * @throws IllegalKeyException 
     * @throws AuthLoginException 
     * @throws AuthStatusException 
     * @throws ObjectNotFoundException 
     * @throws IOException 
     * @throws CertificateException 
     * @throws CertificateEncodingException 
     */
    private Certificate pkcs10CertRequest(Admin administrator, ISignSessionLocal signsession, PKCS10RequestMessage req,
        String username, String password) throws NotFoundException, AuthStatusException, AuthLoginException, IllegalKeyException, CADoesntExistsException, SignRequestException, SignRequestSignatureException, ClassNotFoundException, CertificateEncodingException, CertificateException, IOException {
        Certificate cert=null;
		req.setUsername(username);
        req.setPassword(password);
        IResponseMessage resp = signsession.createCertificate(administrator,req,Class.forName(X509ResponseMessage.class.getName()));
        cert = CertTools.getCertfromByteArray(resp.getResponseMessage());
        return cert;
    } //pkcs10CertReq


}

