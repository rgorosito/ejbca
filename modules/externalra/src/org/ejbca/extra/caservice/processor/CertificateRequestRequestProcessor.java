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

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.jce.netscape.NetscapeCertRequest;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.cesecore.certificates.certificate.request.RequestMessageUtils;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.util.CertTools;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.protocol.cmp.CrmfRequestMessage;
import org.ejbca.extra.db.CertificateRequestRequest;
import org.ejbca.extra.db.CertificateRequestResponse;
import org.ejbca.extra.db.ExtRARequest;
import org.ejbca.extra.db.ISubMessage;
import org.ejbca.util.passgen.IPasswordGenerator;
import org.ejbca.util.passgen.PasswordGeneratorFactory;

/**
 * Process certificate signing requests.
 * 
 * CertificateRequestRequest.REQUEST_TYPE_.. lists supported request types.
 * CertificateRequestRequest.RESPONSE_TYPE.. lists supported response type. Not all responses are available for all request types.
 * 
 * @version $Id$
 */
public class CertificateRequestRequestProcessor extends MessageProcessor implements ISubMessageProcessor {

	private static final Logger log = Logger.getLogger(CertificateRequestRequestProcessor.class);
	
	private static final String MSG_UNSUPPORTED_RESPONSE_TYPE = "Unsupported response type.";
	private static final String MSG_UNSUPPORTED_REQUEST_TYPE = "Unsupported request type.";
	
	/** @see ISubMessageProcessor#process(AuthenticationToken, ISubMessage, String) */
	public ISubMessage process(AuthenticationToken admin, ISubMessage submessage, String errormessage) {
		if (errormessage == null) {
			return processCertificateRequestRequest(admin, (CertificateRequestRequest) submessage);
		} else {
			return new CertificateRequestResponse(((ExtRARequest) submessage).getRequestId(), false, errormessage, null, null);
		}
	}

	/**
	 * Extracts the certificate signing request type and requests a new certificate using the provided credentials.
	 */
	private CertificateRequestResponse processCertificateRequestRequest(AuthenticationToken admin, CertificateRequestRequest submessage) {
		if (log.isDebugEnabled()) {
			log.debug("Processing CertificateRequestRequest");
		}
		try {
	        byte[] result = null;
	        if (submessage.createOrEditUser()) {
				if (log.isDebugEnabled()) {
					log.debug("createOrEditUser == true, will use one-shot request processing.");
				}
		        final EndEntityInformation userdatavo = getUserDataVO(admin, submessage);
		        final String requestData = new String(submessage.getRequestData()); 
		        final int requestTypeInt = submessage.getRequestType();
		        final int responseTypeInt = submessage.getResponseType();
		        
		        final String hardTokenSN = null;
		        result = certificateRequestSession.processCertReq(
		        		admin, 
		        		userdatavo, 
		        		requestData, 
		        		requestTypeInt,
		        		hardTokenSN, 
		        		responseTypeInt); 	        	
	        } else {
	        	AuthenticationToken intAdmin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CertificateRequestProcessor"));
		        switch (submessage.getRequestType()) {
		        case CertificateRequestRequest.REQUEST_TYPE_PKCS10:
		        	Certificate cert = null;
		        	PKCS10RequestMessage req = RequestMessageUtils.genPKCS10RequestMessage(submessage.getRequestData());
		        	req.setUsername(submessage.getUsername());
		        	req.setPassword(submessage.getPassword());
		        	ResponseMessage resp = signSession.createCertificate(admin, req, X509ResponseMessage.class, null);
		        	cert = CertTools.getCertfromByteArray(resp.getResponseMessage());
		        	if (submessage.getResponseType() == CertificateRequestRequest.RESPONSE_TYPE_CERTIFICATE) {
		        		result = cert.getEncoded();
		        	} else {  
		        		result = signSession.createPKCS7(admin, cert, true);
		        	}
		        	break;
		        case CertificateRequestRequest.REQUEST_TYPE_SPKAC:
			        ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(submessage.getRequestData()));
			        ASN1Sequence spkac = (ASN1Sequence) in.readObject();
			        in.close();
			        NetscapeCertRequest nscr = new NetscapeCertRequest(spkac);
		            cert = signSession.createCertificate(admin, submessage.getUsername(), submessage.getPassword(), nscr.getPublicKey());
		        	if (submessage.getResponseType() == CertificateRequestRequest.RESPONSE_TYPE_CERTIFICATE) {
		        		result = cert.getEncoded();
		        	} else if (submessage.getResponseType() == CertificateRequestRequest.RESPONSE_TYPE_PKCS7) {  
		        		result = signSession.createPKCS7(admin, cert, true);
		        	} else if (submessage.getResponseType() == CertificateRequestRequest.RESPONSE_TYPE_PKCS7WITHCHAIN) {
		        		// Read certificate chain
		                ArrayList<Certificate> certList = new ArrayList<Certificate>();
	                    certList.add(cert);
	                    certList.addAll(caSession.getCAInfo(intAdmin, CertTools.getIssuerDN(cert).hashCode()).getCertificateChain());
	                    // Create large certificate-only PKCS7
	                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
	                    CertPath certPath = cf.generateCertPath(new ByteArrayInputStream(CertTools.getPEMFromCerts(certList)));
	                    result = certPath.getEncoded("PKCS7");
		        	} else {  
		    			return new CertificateRequestResponse(submessage.getRequestId(), false, MSG_UNSUPPORTED_RESPONSE_TYPE, null, null);
		        	}
		        	break;
		        case CertificateRequestRequest.REQUEST_TYPE_CRMF:
		        	// Extract request in a format that EJBCA can process
					CertReqMessages certReqMessages = CertReqMessages.getInstance(new ASN1InputStream(submessage.getRequestData()).readObject());
					PKIMessage msg = new PKIMessage(new PKIHeader(
							2, new GeneralName(new X500Name("CN=unused")), new GeneralName(new X500Name("CN=unused"))),
							new PKIBody(2, certReqMessages)); // [2] CertReqMessages --Certification Request
		        	CrmfRequestMessage crmfReq = new CrmfRequestMessage(msg, null, true, null);
		        	crmfReq.setUsername(submessage.getUsername());
		        	crmfReq.setPassword(submessage.getPassword());
		        	// Request and extract certificate from response
		        	ResponseMessage response = signSession.createCertificate(admin, crmfReq, org.ejbca.core.protocol.cmp.CmpResponseMessage.class, null);
		        	ASN1InputStream ais = new ASN1InputStream(new ByteArrayInputStream(response.getResponseMessage()));
		        	CertRepMessage certRepMessage = (CertRepMessage) PKIMessage.getInstance(ais.readObject()).getBody().getContent();
					InputStream inStream = new ByteArrayInputStream(certRepMessage.getResponse()[0].getCertifiedKeyPair().getCertOrEncCert().getCertificate().getEncoded());
					cert = CertificateFactory.getInstance("X.509").generateCertificate(inStream);
					inStream.close();
					// Convert to the right response type
		        	if (submessage.getResponseType() == CertificateRequestRequest.RESPONSE_TYPE_CERTIFICATE) {
		        		result = cert.getEncoded();
		        	} else if (submessage.getResponseType() == CertificateRequestRequest.RESPONSE_TYPE_PKCS7) {  
		        		result = signSession.createPKCS7(admin, cert, false);
		        	} else if (submessage.getResponseType() == CertificateRequestRequest.RESPONSE_TYPE_PKCS7WITHCHAIN) {
		        		// Read certificate chain
		                ArrayList<Certificate> certList = new ArrayList<Certificate>();
	                    certList.add(cert);
	                    certList.addAll(caSession.getCAInfo(intAdmin, CertTools.getIssuerDN(cert).hashCode()).getCertificateChain());
	                    // Create large certificate-only PKCS7
	                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
	                    CertPath certPath = cf.generateCertPath(new ByteArrayInputStream(CertTools.getPEMFromCerts(certList)));
	                    result = certPath.getEncoded("PKCS7");
		        	} else {
		    			return new CertificateRequestResponse(submessage.getRequestId(), false, MSG_UNSUPPORTED_RESPONSE_TYPE, null, null);
		        	}
		        	break;
	        	default:
	    			return new CertificateRequestResponse(submessage.getRequestId(), false, MSG_UNSUPPORTED_REQUEST_TYPE, null, null);
		        }
	        }
	        
	        // Return the response when we have response data (byte[])
	        return new CertificateRequestResponse(submessage.getRequestId(), true, null, submessage.getResponseType(), result);
		} catch (Exception e) {
			if (log.isDebugEnabled()) {
				log.debug("External RA request generated an error: " + e.getMessage());
			}
			return new CertificateRequestResponse(submessage.getRequestId(), false, "Error " + e.getMessage(), null, null);
		}
	}
	
	private EndEntityInformation getUserDataVO(final AuthenticationToken admin, final CertificateRequestRequest submessage) throws ClassCastException, EjbcaException, CADoesntExistsException, AuthorizationDeniedException {
		final EndEntityInformation result = generateUserDataVO(admin, submessage);
		
		result.setStatus(EndEntityConstants.STATUS_NEW);
		
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
