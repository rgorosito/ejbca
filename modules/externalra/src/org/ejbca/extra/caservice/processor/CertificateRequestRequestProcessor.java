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
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.netscape.NetscapeCertRequest;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.protocol.IResponseMessage;
import org.ejbca.core.protocol.PKCS10RequestMessage;
import org.ejbca.core.protocol.X509ResponseMessage;
import org.ejbca.core.protocol.cmp.CrmfRequestMessage;
import org.ejbca.extra.db.CertificateRequestRequest;
import org.ejbca.extra.db.CertificateRequestResponse;
import org.ejbca.extra.db.ExtRARequest;
import org.ejbca.extra.db.ISubMessage;
import org.ejbca.util.CertTools;
import org.ejbca.util.RequestMessageUtils;

import com.novosec.pkix.asn1.cmp.CertRepMessage;
import com.novosec.pkix.asn1.cmp.PKIBody;
import com.novosec.pkix.asn1.cmp.PKIHeader;
import com.novosec.pkix.asn1.cmp.PKIMessage;
import com.novosec.pkix.asn1.crmf.CertReqMessages;

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
	
	/** @see ISubMessageProcessor#process(Admin, ISubMessage, String) */
	public ISubMessage process(Admin admin, ISubMessage submessage, String errormessage) {
		if (errormessage == null) {
			return processCertificateRequestRequest(admin, (CertificateRequestRequest) submessage);
		} else {
			return new CertificateRequestResponse(((ExtRARequest) submessage).getRequestId(), false, errormessage, null, null);
		}
	}

	/**
	 * Extracts the certificate signing request type and requests a new certificate using the provided credentials.
	 */
	private CertificateRequestResponse processCertificateRequestRequest(Admin admin, CertificateRequestRequest submessage) {
		log.debug("Processing CertificateRequestRequest");
		try {
	        byte[] result = null;	
	        switch (submessage.getRequestType()) {
	        case CertificateRequestRequest.REQUEST_TYPE_PKCS10:
	        	Certificate cert = null;
	        	PKCS10RequestMessage req = RequestMessageUtils.genPKCS10RequestMessage(submessage.getRequestData());
	        	req.setUsername(submessage.getUsername());
	        	req.setPassword(submessage.getPassword());
	        	IResponseMessage resp = signSession.createCertificate(admin, req, X509ResponseMessage.class, null);
	        	cert = CertTools.getCertfromByteArray(resp.getResponseMessage());
	        	if (submessage.getResponseType() == CertificateRequestRequest.RESPONSE_TYPE_ENCODED) {
	        		result = cert.getEncoded();
	        	} else {  
	        		result = signSession.createPKCS7(admin, cert, true);
	        	}
	        	break;
	        case CertificateRequestRequest.REQUEST_TYPE_KEYGEN:
		        ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(submessage.getRequestData()));
		        ASN1Sequence spkac = (ASN1Sequence) in.readObject();
		        in.close();
		        NetscapeCertRequest nscr = new NetscapeCertRequest(spkac);
	            cert = signSession.createCertificate(admin, submessage.getUsername(), submessage.getPassword(), nscr.getPublicKey());
	        	if (submessage.getResponseType() == CertificateRequestRequest.RESPONSE_TYPE_ENCODED) {
	        		result = cert.getEncoded();
	        	} else if (submessage.getResponseType() == CertificateRequestRequest.RESPONSE_TYPE_PKCS7) {  
	        		result = signSession.createPKCS7(admin, cert, true);
	        	} else if (submessage.getResponseType() == CertificateRequestRequest.RESPONSE_TYPE_UNSIGNEDPKCS7) {
	        		// Read certificate chain
	                ArrayList<Certificate> certList = new ArrayList<Certificate>();
                    certList.add(cert);
                    certList.addAll(caSession.getCA(Admin.getInternalAdmin(), CertTools.getIssuerDN(cert).hashCode()).getCertificateChain());
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
						new DERInteger(2), new GeneralName(new X509Name("CN=unused")), new GeneralName(new X509Name("CN=unused"))),
						new PKIBody(certReqMessages, 2)); // [2] CertReqMessages --Certification Request
	        	CrmfRequestMessage crmfReq = new CrmfRequestMessage(msg, null, true, null);
	        	crmfReq.setUsername(submessage.getUsername());
	        	crmfReq.setPassword(submessage.getPassword());
	        	// Request and extract certificate from response
	        	IResponseMessage response = signSession.createCertificate(admin, crmfReq, org.ejbca.core.protocol.cmp.CmpResponseMessage.class, null);
	        	ASN1InputStream ais = new ASN1InputStream(new ByteArrayInputStream(response.getResponseMessage()));
	        	CertRepMessage certRepMessage = PKIMessage.getInstance(ais.readObject()).getBody().getCp();
				InputStream inStream = new ByteArrayInputStream(certRepMessage.getResponse(0).getCertifiedKeyPair().getCertOrEncCert().getCertificate().getEncoded());
				cert = CertificateFactory.getInstance("X.509").generateCertificate(inStream);
				inStream.close();
				// Convert to the right response type
	        	if (submessage.getResponseType() == CertificateRequestRequest.RESPONSE_TYPE_ENCODED) {
	        		result = cert.getEncoded();
	        	} else if (submessage.getResponseType() == CertificateRequestRequest.RESPONSE_TYPE_PKCS7) {  
	        		result = signSession.createPKCS7(admin, cert, false);
	        	} else if (submessage.getResponseType() == CertificateRequestRequest.RESPONSE_TYPE_UNSIGNEDPKCS7) {
	        		// Read certificate chain
	                ArrayList<Certificate> certList = new ArrayList<Certificate>();
                    certList.add(cert);
                    certList.addAll(caSession.getCA(Admin.getInternalAdmin(), CertTools.getIssuerDN(cert).hashCode()).getCertificateChain());
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
	        return new CertificateRequestResponse(submessage.getRequestId(), true, null, submessage.getResponseType(), result);
		} catch (Exception e) {
			log.debug("External RA request generated an error: " + e.getMessage());
			return new CertificateRequestResponse(submessage.getRequestId(), false, "Error " + e.getMessage(), null, null);
		}
	}
}
