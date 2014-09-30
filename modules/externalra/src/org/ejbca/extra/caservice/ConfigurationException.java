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
package org.ejbca.extra.caservice;

/**
 * Execption thrown if service is badly configured or cannot lookup context
 * 
 * @author Philip Vendil
 *
 */
public class ConfigurationException extends Exception {
	        
	private static final long serialVersionUID = 1L;

	/**
     * Constructs an instance of <code>ConfigurationException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public ConfigurationException(String msg) {    	
        super(msg);        
    }
    
    public ConfigurationException(String msg, Exception e) {    	
        super(msg,e);        
    }


}
