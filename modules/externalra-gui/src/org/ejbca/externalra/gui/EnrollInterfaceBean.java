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
 
package org.ejbca.externalra.gui;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.List;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

import javax.faces.application.FacesMessage;
import javax.faces.context.FacesContext;
import javax.faces.event.ActionEvent;
import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.netscape.NetscapeCertRequest;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.FileTools;
import org.ejbca.config.InternalConfiguration;
import org.ejbca.core.model.SecConst;
import org.ejbca.extra.db.CertificateRequestRequest;

import com.icesoft.faces.component.inputfile.InputFile;
import com.icesoft.faces.context.ByteArrayResource;
import com.icesoft.faces.context.Resource;
import com.icesoft.faces.context.effects.JavascriptContext;

/**
 * This is the backing bean for the enrollment part of the External RA GUI.
 * 
 * @version $Id$
 */
public class EnrollInterfaceBean {

	private static final String PEM_CSR_BEGIN       = "-----BEGIN CERTIFICATE REQUEST-----";
	private static final String PEM_CSR_END         = "-----END CERTIFICATE REQUEST-----";
	private static final String PEM_CSR_BEGIN_VISTA = "-----BEGIN NEW CERTIFICATE REQUEST-----";
	private static final String PEM_CSR_END_VISTA   = "-----END NEW CERTIFICATE REQUEST-----";
	private static final String PEM_PKCS7_BEGIN     = "-----BEGIN PKCS7-----";
	private static final String PEM_PKCS7_END       = "-----END PKCS7-----";

	private static final Logger log = Logger.getLogger(EnrollInterfaceBean.class);

	private IRequestDispatcher requestDispatcher = null;
	
	// General variables
	private String userAgentString = null;
	private String username = null;
	private String password = null;
	private boolean showPassword = false;
	private String filename = null;
	private Resource resource = null;
	private String mimeType = null;
	
	// Variables used to get a certificate from a CSR
	private String certificateRequest = PEM_CSR_BEGIN + "\n...base 64 encoded request...\n" + PEM_CSR_END;
	private String requestedResponseType = "der";

	private String certificateRequestType = null;
	private String certificateResponse = "";
	private String certificateResponseType = null;
	
	private String cspSelectValue = null;
	
	public String getUsername() { return username; }
	public void setUsername(String username) { this.username = username; }
	public String getPassword() { return password; }
	public void setPassword(String password) { this.password = password; }
	public boolean getShowPassword() { return showPassword; }
	public void setShowPassword(boolean showPassword) { this.showPassword = showPassword; }
	
	public boolean isDownloadAvailable() { return resource!=null; }
	public String getFilename() { return filename; }
	public Resource getResource() { return resource; }
	public String getMimeType() { return mimeType; }
	
	public String getCertificateRequest() { return certificateRequest; }
	public void setCertificateRequest(String certificateRequest) { this.certificateRequest = certificateRequest; }
	public String getRequestedResponseType() { return requestedResponseType; }
	public void setRequestedResponseType(String requestedResponseType) { this.requestedResponseType = requestedResponseType; }

	public String getCertificateRequestType() { return certificateRequestType; }
	public void setCertificateRequestType(String certificateRequestType) { this.certificateRequestType = certificateRequestType; }
	public String getCertificateResponseType() { return certificateResponseType; }
	public String getCertificateResponse() { return certificateResponse; }
	public void setCertificateResponse(String certificateResponse) { this.certificateResponse = certificateResponse; }
	
	public String getCspSelectValue() { return cspSelectValue; }
	public void setCspSelectValue(String cspSelectValue) { this.cspSelectValue = cspSelectValue; }
	
	public String getKeySpec() { return ExternalRaGuiConfiguration.getKeySpec(); }
	public String getExportable() { return ExternalRaGuiConfiguration.getExportable() ? "1" : "0"; }

	public String getVersionString() { return InternalConfiguration.getAppVersionNumber() + " (" + InternalConfiguration.getSvnRevision() + ")"; }
	public String getHelpUrl() { return ExternalRaGuiConfiguration.getHelpUrl(); }

	/** @return The host's name or "unknown" if it could not be determined. */
    public String getHostName() {
    	String hostname = "unknown";
    	try {
	        hostname = InetAddress.getLocalHost().getHostName();
	    } catch (UnknownHostException e) {
	    	// Ignored
	    }
	    return hostname;
    }

    /** @return true if the user-agent String contains MSIE **/ 
	public boolean isInternetExplorer() {
		return getUserAgenString().indexOf("MSIE") != -1;
	}

	/**
	 * XEnroll:
	 *  "Windows NT 5.1" = Win XP x86
	 *  "Windows NT 5.2" = Win XP x64, Server 2003
	 * CertEnroll:
	 *  "Windows NT 6.0" = Win Vista, Server 2008
	 *  "Windows NT 6.1" = Windows 7, Server 2008 R2
	 */
	public boolean isWindowsNT5() {
		return getUserAgenString().indexOf("Windows NT 5.") != -1;
	}

	/**
	 * Prevent the web framework from rendering an empty table if there are no global messages
	 * by using this method. Empty tables results in error messages in the Safari log.
	 */
	public boolean isMessagesPending() {
		return FacesContext.getCurrentInstance().getMessages(null).hasNext();
	}

	/**
	 * @return the current user-agent string that identifies the clients browser and operating system. 
	 */
	private String getUserAgenString() {
		if (userAgentString == null) {
			userAgentString = (String) FacesContext.getCurrentInstance().getExternalContext().getRequestHeaderMap().get("user-agent");
			log.debug("User agent: " + userAgentString);
		}
		return userAgentString;
	}

	/**
	 * @return an implementation for communication with the EJBCA instance.
	 */
	private IRequestDispatcher getRequestDispatcher() {
		if (requestDispatcher == null) {
			// Change this to read the class name from the externalra-gui configuration if we add additional implementations.
			String className = ExternalRARequestDispatcher.class.getName();
			try {
				requestDispatcher = (IRequestDispatcher) Class.forName(className).newInstance();
			} catch (ClassNotFoundException e) {
				log.error("Could not find request implementaion :" + className);
			} catch (InstantiationException e) {
				log.error("Could not instantiate request implementaion :" + className);
			} catch (IllegalAccessException e) {
				log.error("Could not access request implementaion :" + className);
			}
		}
		return requestDispatcher; 
	}

	/**
	 * Used for reading a Certificate Signing Request file upload into the certificate request String.
	 * @param actionEvent is the parameter from the web framework containing the file.
	 */
	public void uploadActionListener(ActionEvent actionEvent) {
        InputFile inputFile = (InputFile) actionEvent.getSource();
		FacesContext context = FacesContext.getCurrentInstance();
        if (inputFile.getFileInfo().isSaved()) {
        	// Validate that it is a CSR..
        	File f = inputFile.getFileInfo().getFile();
            // Assume this is a small file.. it should be..
            long len = f.length();
            if (len < 16*1024L) {
                byte[] buf = new byte[(int) len];
                try {
                    FileInputStream in = new FileInputStream(f);
                    in.read(buf);
                    in.close();
                } catch (IOException e) {
                	context.addMessage(null /*actionEvent.getComponent().getClientId(context)*/, new FacesMessage(FacesMessage.SEVERITY_ERROR, getMessage("enroll.csrcert.uploadfailed"), null));
                	log.debug("Rejected uploaded file due to IOException.");
                	return;
				}
                try {
                    // See if it was a PEM
                	buf = FileTools.getBytesFromPEM(buf, PEM_CSR_BEGIN, PEM_CSR_END);
                } catch (IOException e) {
                	log.debug("Uploaded file was not a PEM.. tryin to parse it as a DER encoded request.");
                }
                // See if it as a PKCS10
                try {
                    new PKCS10CertificationRequest(buf);
                } catch (Exception e) {
                	context.addMessage(null /*actionEvent.getComponent().getClientId(context)*/, new FacesMessage(FacesMessage.SEVERITY_ERROR, getMessage("enroll.csrcert.uploadfailednotpkcs10"), null));
                	log.debug("Rejected uploaded file since it's not a valid PKCS#10 request.");
                	return;
                }
            	// Convert it back to a PEM
                String pem = PEM_CSR_BEGIN + "\n" + new String(Base64.encode(buf)) + "\n" + PEM_CSR_END;
                certificateRequest = pem;
            	context.addMessage(null /*actionEvent.getComponent().getClientId(context)*/, new FacesMessage(FacesMessage.SEVERITY_INFO, getMessage("enroll.csrcert.uploadok"), null));
            } else {
            	context.addMessage(null /*actionEvent.getComponent().getClientId(context)*/, new FacesMessage(FacesMessage.SEVERITY_ERROR, getMessage("enroll.csrcert.uploadfailedtoolarge"), null));
            }
        } else {
        	log.debug("File upload failed: " + inputFile.getFileInfo().getException().getMessage());
    		context.addMessage(null /*actionEvent.getComponent().getClientId(context)*/, new FacesMessage(FacesMessage.SEVERITY_ERROR, getMessage("enroll.csrcert.uploadfailed"), null));
        }
	}
	
	/**
	 * Action that requests a KeyStore from EJBCA using the given credentials.
	 */
	public void createKeystore() {
		log.info("Recieved a KeyStore request for username '" + username + "' from " + getRemoteAddress());
		FacesContext context = FacesContext.getCurrentInstance();
		if (username==null || username.length()==0 || password==null || password.length()==0) {
			context.addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, getMessage("enroll.incompletefields"), null));
			return;
		}
		// Request the KeyStore from the CA
		ResponseInformation keyStoreResponse = getRequestDispatcher().getKeyStoreResponse(username, password);
		// Check if got a valid result
		if (keyStoreResponse == null) {
			context.addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, getMessage("enroll.noresponse"), null));
			log.error("KeyStore request for '" + username + "' failed. No response from CA.");
			return;
		} else if (keyStoreResponse.getErrorMessage() != null) {
			context.addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, getMessage("enroll.keystore.couldnotcreate"), null));
			log.info("KeyStore request for '" + username + "' failed. " + keyStoreResponse.getErrorMessage());
			return;
		}
		// Handle response
		resource = new ByteArrayResource(keyStoreResponse.getResponseInformation());
		switch (keyStoreResponse.getResponseType()) {
		case SecConst.TOKEN_SOFT_JKS:
			filename = username + ".jks";
			break;
		case SecConst.TOKEN_SOFT_P12:
			filename = username + ".p12";
			break;
		case SecConst.TOKEN_SOFT_PEM:
			filename = username + ".pem";
			break;
		default:
			filename = username + ".unknown";
			break;
		}
		mimeType = "application/octet-stream";
		log.info("KeyStore request with response-type " + keyStoreResponse.getResponseType() + " for '" + username + "' was successful.");
	}
	
	/**
	 * Action that requests a certificate from EJBCA using the given credentials and the Certificate Signing Request.
	 */
	public void createCertFromCSR() {
		log.info("Recieved a certificate signing request for username '" + username + "' from " + getRemoteAddress());
		if (log.isDebugEnabled()) {
			log.debug("certificateRequest: " + certificateRequest);
		}
		FacesContext context = FacesContext.getCurrentInstance();
		if (username==null || username.length()==0 || password==null || password.length()==0 || certificateRequest==null || certificateRequest.length()==0) {
			context.addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, getMessage("enroll.incompletefields"), null));
			return;
		}
		// Verify that we got a valid Certificate Signing Request
		try {
        	// Clean it up if windows has messed it up..
            byte[] buf = (PEM_CSR_BEGIN + certificateRequest.replaceFirst(PEM_CSR_BEGIN, "").replaceFirst(PEM_CSR_END, "").replaceAll(" ", "").replaceAll("\r", "")+PEM_CSR_END).getBytes();
            // See if it is a PEM
			buf = FileTools.getBytesFromPEM(buf, PEM_CSR_BEGIN, PEM_CSR_END);
			certificateRequest = PEM_CSR_BEGIN + "\n" + new String(Base64.encode(buf)) + "\n" + PEM_CSR_END;
			if (log.isDebugEnabled()) {
	            log.debug("cleaned req: " + certificateRequest);
			}
            new PKCS10CertificationRequest(buf);
		} catch (Exception e) {
			context.addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, getMessage("enroll.invalidreqdata"), null));
			return;
		}
		// Determine what kind of response the user has requested
		int responseType = CertificateRequestRequest.RESPONSE_TYPE_ENCODED;
		if ("pkcs7".equals(requestedResponseType)) {
			responseType = CertificateRequestRequest.RESPONSE_TYPE_PKCS7;
		}
		// Request the certificate from the CA
		ResponseInformation csrResponse = getRequestDispatcher().getCertificateSigningRequestResponse(username, password, certificateRequest, responseType);
		// Check if got a valid result
		if (csrResponse == null) {
			context.addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, getMessage("enroll.noresponse"), null));
			log.error("Certificate request for '" + username + "' failed. No response from CA.");
			return;
		} else if (csrResponse.getErrorMessage() != null) {
			context.addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, getMessage("enroll.csrcert.couldnotcreate"), null));
			log.info("Certificate request for '" + username + "' failed. " + csrResponse.getErrorMessage());
			return;
		}
		// Handle response
		switch (csrResponse.getResponseType()) {
		case CertificateRequestRequest.RESPONSE_TYPE_ENCODED:
			if ("pem".equals(requestedResponseType)) {
				Certificate[] certs = new Certificate[1];
				try {
					certs[0] = CertTools.getCertfromByteArray(csrResponse.getResponseInformation());
					resource = new ByteArrayResource(CertTools.getPEMFromCerts(CertTools.getCertCollectionFromArray(certs, "BC")));
					filename = username + ".pem";
					mimeType = "application/x-pem-file";
				} catch (Exception e) {
					log.error("",e);
					context.addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, getMessage("enroll.invalidresponse"), null));
				}
			} else {
				resource = new ByteArrayResource(csrResponse.getResponseInformation());
				filename = username + ".der";
				mimeType = "application/pkix-cert";
			}
			break;
		case CertificateRequestRequest.RESPONSE_TYPE_PKCS7:
			resource = new ByteArrayResource(csrResponse.getResponseInformation());
			filename = username + ".p7b";
			mimeType = "application/x-pkcs7-certificates";
			break;
		default:
			filename = username + ".unknown";
			mimeType = "application/octet-stream";
			break;
		}
		log.info("Certificate request with response-type " + csrResponse.getResponseType() + " for '" + username + "' was successful.");
	}

	/**
	 * Action that requests a certificate from EJBCA using the given credentials and the Certificate Signing Request created by the browser.
	 */
	public void createCertFromBrowser() {
		log.info("Recieved a browser generated certificate request of type " + certificateRequestType + " for username '" + username + "' from " + getRemoteAddress());
		if (log.isDebugEnabled()) {
			log.debug("certificateRequest: " + certificateRequest);
		}
		FacesContext context = FacesContext.getCurrentInstance();
		if (username==null || username.length()==0 || password==null || password.length()==0 || certificateRequest==null || certificateRequest.length()==0
				|| certificateRequestType==null || certificateRequestType.length()==0) {
			context.addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, getMessage("enroll.incompletefields"), null));
			return;
		}
		// Verify that we got a valid certificate request and determine response type
		byte[] buf = null;
		int requestType = Integer.parseInt(certificateRequestType);
		int responseType;
		switch (requestType) {
		case CertificateRequestRequest.REQUEST_TYPE_CRMF:
			responseType = CertificateRequestRequest.RESPONSE_TYPE_PKCS7;
			buf = Base64.decode(certificateRequest.getBytes());
			ASN1InputStream asn1InputStream = new ASN1InputStream(buf);
			try {
				// Verify that we can parse this as a CRMF object
				CertReqMessages.getInstance(asn1InputStream.readObject()).toCertReqMsgArray()[0].toASN1Primitive();
			} catch (IOException e) {
				context.addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, getMessage("enroll.invalidreqdata"), null));
				log.error("",e);
			}
			break;
		case CertificateRequestRequest.REQUEST_TYPE_PKCS10: 
			responseType = CertificateRequestRequest.RESPONSE_TYPE_PKCS7;
			try {
				if (!isWindowsNT5()) {
					responseType = CertificateRequestRequest.RESPONSE_TYPE_UNSIGNEDPKCS7;
				}
				// Replace Vista PEM markers
				certificateRequest = certificateRequest.replaceAll(PEM_CSR_BEGIN_VISTA, PEM_CSR_BEGIN);
				certificateRequest = certificateRequest.replaceAll(PEM_CSR_END_VISTA, PEM_CSR_END);
				if (certificateRequest.indexOf(PEM_CSR_BEGIN) == -1) {
					certificateRequest = PEM_CSR_BEGIN + "\n" + certificateRequest + "\n" + PEM_CSR_END;
				}
				buf = FileTools.getBytesFromPEM(certificateRequest.getBytes(), PEM_CSR_BEGIN, PEM_CSR_END);
	            new PKCS10CertificationRequest(buf);
			} catch (Exception e) {
				log.error("",e);
				context.addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, getMessage("enroll.invalidreqdata"), null));
				return;
			}
			break;
		case CertificateRequestRequest.REQUEST_TYPE_KEYGEN: 
			responseType = CertificateRequestRequest.RESPONSE_TYPE_PKCS7;
			try {
				buf = Base64.decode(certificateRequest.getBytes());
		        ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(buf));
		        ASN1Sequence spkac = (ASN1Sequence) in.readObject();
		        in.close();
		        NetscapeCertRequest nscr = new NetscapeCertRequest(spkac);
		        // Verify POPO, we don't care about the challenge, it's not important.
		        nscr.setChallenge("challenge");
		        if (nscr.verify("challenge") == false) {
					context.addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, getMessage("enroll.invalidreqdata"), null));
					return;
		        }
			} catch (Exception e) {
				log.error("",e);
				context.addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, getMessage("enroll.invalidreqdata"), null));
				return;
			}
			break;
		case -1:
			// This is a workaround to hide errors when we use the KeyGenServlet..
			return;
		default:
			context.addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, getMessage("enroll.unknownrequesttype"), null));
			return;
		}
		// Request the certificate from the CA
		if (log.isDebugEnabled()) {
			log.debug("Got requestType " + requestType + " and is expecting responseType " + responseType + " for user " + username);
		}
		ResponseInformation responseData = getRequestDispatcher().getCertificateResponse(username, password, requestType, buf, responseType);
		// Check if got a valid result
		if (responseData == null) {
			context.addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, getMessage("enroll.noresponse"), null));
			log.error("Certificate request for '" + username + "' failed. No response from CA.");
			return;
		} else if (responseData.getErrorMessage() != null) {
			context.addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, getMessage("enroll.browsercert.couldnotcreate"), null));
			log.info("Certificate request for '" + username + "' failed. " + responseData.getErrorMessage());
			return;
		}
		// Handle response
		certificateResponseType = "" + responseData.getResponseType();
		switch (responseData.getResponseType()) {
		case CertificateRequestRequest.RESPONSE_TYPE_PKCS7:
			if (isInternetExplorer()) {
				// Working for XP+IE7
				certificateResponse = new String(Base64.encode(responseData.getResponseInformation(), false));
			} else {
				resource = new ByteArrayResource(responseData.getResponseInformation());
				mimeType = "application/x-x509-user-cert";
			}
			break;
		case CertificateRequestRequest.RESPONSE_TYPE_UNSIGNEDPKCS7:
			// Working for Vista+IE8
			certificateResponse = new String(Base64.encode(responseData.getResponseInformation(), false));
            try {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                String pkcs7 = PEM_PKCS7_BEGIN + "\n" + new String(Base64.encode(responseData.getResponseInformation(), true)) + "\n" + PEM_PKCS7_END + "\n";
                log.debug("pkcs7="+pkcs7);
            	CertPath certPath = cf.generateCertPath(new ByteArrayInputStream(responseData.getResponseInformation()), "PKCS7");
            	List<? extends Certificate> certList = certPath.getCertificates();
            	Certificate caCert = certList.get(certList.size()-1);
            	String caCertificate = new String(Base64.encode(caCert.getEncoded(), false));
				resource = new ByteArrayResource(caCertificate.getBytes());
				mimeType = "application/x-x509-ca-cert";
            } catch (CertificateException e) {
            	e.printStackTrace();
            }
    		if (log.isDebugEnabled()) {
    			log.debug("certificateResponse: " + certificateResponse);
    		}
			break;
		default:
			context.addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, getMessage("enroll.unknownresponsetype"), null));
			log.error("Unknown result type: " + certificateResponseType);
			break;
		}
		log.info("Certificate request with response-type " + responseData.getResponseType() + " for '" + username + "' was successful.");
	}
	
	/**
	 * Adds a JavaScript that removes the HTML from where it was called. Expects to be included inside a div with id "form:downloadDiv2".
	 */
	public void removeLinks() {
		// Hide the installer links once the cert is installed 
		JavascriptContext.addJavascriptCall(FacesContext.getCurrentInstance(), "if (document.getElementById('form:certificateInstalled').value == 'true') { document.getElementById('form:downloadLinkDiv2').innerHTML = 'Installed.';}");
	}
	
	/**
	 * Action that does absolutely nothing. Used when we want a commandLink to just trigger an onclick or something similar.
	 */
	public void noOp() { }
	
	/**
	 * Get localized message from the message-bundle.
	 */
	private String getMessage(String key){
		String text = null;
		FacesContext context = FacesContext.getCurrentInstance();
		ResourceBundle bundle = ResourceBundle.getBundle(context.getApplication().getMessageBundle(), context.getViewRoot().getLocale(), Thread.currentThread().getContextClassLoader());
		try{
			text = bundle.getString(key);
		} catch(MissingResourceException e){
			text = "?? key " + key + " not found ??";
		}
		return text;
	}
	
	private String getRemoteAddress() {
		return ((HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest()).getRemoteAddr();
	}
}
