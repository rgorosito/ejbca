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

import org.bouncycastle.util.encoders.Base64;

/**
 * Response message containing a keystore or an error message.
 * 
 * @version $Id$
 */
public class KeyStoreRetrievalResponse extends ExtRAResponse {

	private static final long serialVersionUID = 1L;

	static final int CLASS_TYPE = 14; // Must be unique to all submessage classes

	public static final float LATEST_VERSION = (float) 1.0;
	
	public static final String KEYSTORE_TYPE     = "keystoretype";
	public static final String KEYSTORE          = "keystore";

	/** Constructor used when loaded from a persisted state */	
	public KeyStoreRetrievalResponse() {}

	/**
	 * Create a new message.
	 * 
	 * @param requestId should be the same unique identifier as in the request.
	 * @param success true if the request was successful
	 * @param failinfo description of the error if the request was unsuccessful
	 * @param keyStoreType One of SecConst.TOKEN_SOFT_...
	 * @param keyStore byte encoded keyStore object
	 * 
	 * @see org.ejbca.extra.db.ExtRAResponse#ExtRAResponse(long, boolean, String)
	 */
	public KeyStoreRetrievalResponse(long requestId, boolean success, String failinfo, Integer keyStoreType, byte[] keyStore) {
        super(requestId, success, failinfo);
		data.put(VERSION, Float.valueOf(LATEST_VERSION));
		data.put(CLASSTYPE, Integer.valueOf(CLASS_TYPE));
		data.put(KEYSTORE_TYPE, keyStoreType);
		if (keyStore != null) {
			data.put(KEYSTORE, new String(Base64.encode(keyStore)));
		} else {
			data.put(KEYSTORE, null);
		}
	}
	
	/** @see org.ejbca.core.model.IUpgradeableData#getLatestVersion() */
	public float getLatestVersion() { return LATEST_VERSION; }
	
	/** @see org.ejbca.core.model.IUpgradeableData#upgrade() */
	public void upgrade() {
		if (LATEST_VERSION != getVersion()) {						
			data.put(VERSION, new Float(LATEST_VERSION));
		}
	}

	/** @return the encoded keystore */
	public byte[] getKeyStoreData() {
		return Base64.decode(((String)data.get(KEYSTORE)).getBytes());
	}

	/** @return one of SecConst.TOKEN_SOFT_... */
	public int getKeyStoreType() {
		return ((Integer)data.get(KEYSTORE_TYPE)).intValue();
	}
}
