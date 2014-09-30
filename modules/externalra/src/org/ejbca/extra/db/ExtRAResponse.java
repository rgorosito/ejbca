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

import org.cesecore.internal.UpgradeableDataHashMap;

/**
 * Abstract base class of the ExtRA Sub Message response. all External RA responses should inherit
 * this class.
 * 
 * Contains the requestId, a flag if operation was successful and a failure message if not. A
 * basic ExtRAResponse will be returned from a ExtRARevokationRequest.
 * 
 * @author philip
 * @version $Id$
 */

public class ExtRAResponse extends UpgradeableDataHashMap implements ISubMessage {

	public static final float LATEST_VERSION = (float) 1.0;

	static final int CLASS_TYPE = 9;
	
		// Field constants
	private static final String REQUESTID              = "REQUESTID";
	private static final String SUCCESS                = "SUCCESS";
	private static final String FAILINFO              = "FAILINFO";	
	
	private static final long serialVersionUID = 1L;
	
	public float getLatestVersion() {
		return LATEST_VERSION;
	}
	
	/**
	 * Default constructor that should be used.
	 * @param success if the request was processed succesfully
	 * @param failinfo the failure information or null, if it was a success
	 */
	public ExtRAResponse(long requestId, boolean success, String failinfo){
		data.put(CLASSTYPE, Integer.valueOf(CLASS_TYPE));
		data.put(VERSION, Float.valueOf(LATEST_VERSION));
        data.put(REQUESTID, Long.valueOf(requestId));
        data.put(SUCCESS, Boolean.valueOf(success));
        data.put(FAILINFO, failinfo);        
	}

	/**
	 * Constructor used when laoded from a persisted state
	 * 
	 */	
	public ExtRAResponse(){}
	
	/**
	 * Returns the reqyest Id assiciated with this sub message.
	 */
	public long getRequestId(){
	   return ((Long) data.get(REQUESTID)).longValue();	
	}
	
	/**
	 * Returns true if the request was sucessful
	 * 
	 */
	public boolean isSuccessful(){
		return ((Boolean) data.get(SUCCESS)).booleanValue();
	}
	
	/**
	 * if the request faild this field returns more information about the failure.
	 */
	public String getFailInfo(){
		return (String) data.get(FAILINFO);
	}

	public void upgrade() {
	}
}
