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
 * Interface for retrieving certificates and keystores from the CA used by the
 * External RA GUI.
 * 
 * @version $Id$
 */
public interface IRequestDispatcher {

	/**
	 * Get a generated KeyStore from the CA in whatever format that is configured
	 * for the end entity. 
	 * @param username The end entity identifier
	 * @param password The shared secret
	 * @return a populated ResponseData object
	 */
	public ResponseInformation getKeyStoreResponse(String username, String password);

	/**
	 * Create a certificate or certificate chain from a Certificate Signing Request
	 * @param username The end entity identifier
	 * @param password The shared secret
	 * @param certificateRequest PEM encoded PKCS#10 request 
	 * @param responseType the desired response format. One of CertificateRequestRequest.RESPONSE_TYPE_..
	 * @return a populated ResponseData object
	 */
	public ResponseInformation getCertificateSigningRequestResponse(String username,
			String password, String certificateRequest, int responseType);

	/**
	 * Create a certificate or certificate chain from a Certificate Signing Request by a browser
	 * @param username The end entity identifier
	 * @param password The shared secret
	 * @param requestType One of CertificateRequestRequest.REQUEST_TYPE_..
	 * @param buf the encoded signing request in the format specified by the requestType parameter
	 * @param responseType the desired response format. One of CertificateRequestRequest.RESPONSE_TYPE_..
	 * @return a populated ResponseData object
	 */
	public ResponseInformation getCertificateResponse(String username,
			String password, int requestType, byte[] buf, int responseType);

}
