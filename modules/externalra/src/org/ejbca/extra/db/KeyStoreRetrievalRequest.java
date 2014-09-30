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

/**
 * Request message for generation or revocation of a keystore.
 * 
 * @version $Id$
 */
public class KeyStoreRetrievalRequest extends ExtRARequest {

	private static final long serialVersionUID = 1L;
	
	static final int CLASS_TYPE = 13; // Must be unique to all submessage classes

	public static final float LATEST_VERSION = (float) 1.0;
	
	private static final String PASSWORD = "password";

	/** Constructor used when loaded from a persisted state */	
	public KeyStoreRetrievalRequest() {}

	/**
	 * Create a new message.
	 * 
	 * @param requestId should be unique.
	 * @param username The end entity identifier
	 * @param password The shared secret
	 */
	public KeyStoreRetrievalRequest(long requestId, String username, String password) {
		data.put(VERSION, Float.valueOf(LATEST_VERSION));
		data.put(CLASSTYPE, Integer.valueOf(CLASS_TYPE));
		data.put(REQUESTID, Long.valueOf(requestId));
		data.put(USERNAME, username);
		data.put(PASSWORD, password);
	}

	/** @see org.ejbca.core.model.IUpgradeableData#getLatestVersion() */
	public float getLatestVersion() { return LATEST_VERSION; }
	
	/** @see org.ejbca.core.model.IUpgradeableData#upgrade() */
	public void upgrade() {
		if (LATEST_VERSION != getVersion()) {						
			data.put(VERSION, new Float(LATEST_VERSION));
		}
	}
	
	/** Returns the password used in this request. */
	public String getPassword() {
		return (String) data.get(PASSWORD);
	}
}
