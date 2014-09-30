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

import java.io.IOException;
import java.io.OutputStream;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;

/**
 * This Servlet was created to handle &lt;keygen&gt;-tag requests from AJAX
 * based web clients where forms are not submitted in a regular fashion
 * that triggers key generation and the creation of a certificate signing
 * request.
 * 
 * By creating a form in an &lt;iframe&gt; that POSTs the to this Servlet
 * it is possible to trigger generation and read the result from a JavaScript.
 * 
 * @version $Id$
 */
public class KeyGenServlet extends HttpServlet {

	private static final long serialVersionUID = 1L;
	private static final Logger log = Logger.getLogger(KeyGenServlet.class);

	/**
	 * Handle the POSTed keygen request. The name attribute should be "keygen".
	 * Responds with a form with id "keygenForm" with an hidden input with id
	 * "keygenResult".
	 */
	public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
		Object keygenObject = request.getParameterMap().get("keygen");
		String html = "<html><body>keygen not supported</body></html>";
		if (keygenObject == null) {
			log.info("Received request but <keygen> was not supported in the requesting browser.");
		} else {
			String keyGen = ((String[])keygenObject)[0];
			keyGen = keyGen.substring(0, keyGen.length()-2);	// Remove newline
			html = "<html><body><form id='keygenForm'><input id='keygenResult' type='hidden' value='" + keyGen + "'/></form></body></html>";
		}
		OutputStream os = response.getOutputStream();
		os.write(html.getBytes());
		os.flush();
	}
}
