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

/**
 * Holder of keystore and certificate data from the CA.
 * 
 * @version $Id$
 */
public class ResponseInformation {
	final private byte[] responseInformation;
	final private int responseType;
	final private String errorMessage;
	
	public ResponseInformation(byte[] responseInformation, int responseType, String errorMessage) {
		this.responseInformation = responseInformation;
		this.responseType = responseType;
		this.errorMessage = errorMessage;
	}
	
	/** @return the encoded KeyStore or certificate(s) */
	public byte[] getResponseInformation() { return responseInformation; }
	
	/** @return one of CertificateRequestRequest.RESPONSE_TYPE_... */
	public int getResponseType() { return responseType; }
	
	/** @return an error message if something went wrong or null if the request was successful */
	public String getErrorMessage() { return errorMessage; }
}
