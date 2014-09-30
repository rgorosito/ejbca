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
package org.ejbca.extra.db;

import java.security.cert.X509Certificate;

/**
 * Class returned from the verifySignature method in the ExtRAMsgHelper.
 * 
 * Contains the following information:
 * Signature valid
 * Signers Certificate 
 * Content 
 *  
 * @author Philip Vendil
 * $Id$
 */
public class ParsedSignatureResult {

	private boolean valid = false;
	private X509Certificate signerCert = null;
	private byte[] content = null;

	/**
	 * Default constructor
	 */
	public ParsedSignatureResult(boolean valid, X509Certificate signerCert, byte[] content) {
		this.valid = valid;
		this.signerCert = signerCert;
		this.content = content;
	}

	/**
	 * @return Returns the content.
	 */
	public byte[] getContent() {
		return content;
	}

	/**
	 * @return Returns the signerCert.
	 */
	public X509Certificate getSignerCert() {
		return signerCert;
	}

	/**
	 * @return Returns the valid.
	 */
	public boolean isValid() {
		return valid;
	}
	
	
	
}
