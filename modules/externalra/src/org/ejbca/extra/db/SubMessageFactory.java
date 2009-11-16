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
package org.ejbca.extra.db;

import java.util.HashMap;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Class used to create a ISubMessage depending of it's classtype, 
 * All valid submessages should be registred in the creatInstance method.
 * 
 * 
 * @author philip
 * $Id: SubMessageFactory.java,v 1.2 2006-08-15 10:44:19 anatom Exp $
 */

class SubMessageFactory {
	
	private static final Log log = LogFactory.getLog(SubMessageFactory.class);
	
	static ISubMessage createInstance(HashMap data){
		ISubMessage retval = null;
		int classType = ((Integer) data.get(ISubMessage.CLASSTYPE)).intValue();
		switch(classType){
		case PKCS10Request.CLASS_TYPE:
			retval =  new PKCS10Request();
			log.debug("Class of type PKCS10Request created");
			break;
		case PKCS12Request.CLASS_TYPE:
			retval =  new PKCS12Request();
			log.debug("Class of type PKCS12Request created");
			break;
		case KeyRecoveryRequest.CLASS_TYPE:
			retval =  new KeyRecoveryRequest();
			log.debug("Class of type KeyRecoveryRequest created");
			break;
		case RevocationRequest.CLASS_TYPE:
			retval =  new RevocationRequest();
			log.debug("Class of type RevocationRequest created");
			break;			
		case PKCS10Response.CLASS_TYPE:
			retval =  new PKCS10Response();
			log.debug("Class of type PKCS10Response created");
			break;
		case PKCS12Response.CLASS_TYPE:
			retval =  new PKCS12Response();
			log.debug("Class of type PKCS12Response created");
			break;
		case EditUserRequest.CLASS_TYPE:
			retval =  new EditUserRequest();
			log.debug("Class of type EditUserRequest created");
			break;				
		case ExtRAResponse.CLASS_TYPE:
			retval =  new ExtRAResponse();
			log.debug("Class of type Response created");
			break;			
        case CardRenewalRequest.CLASS_TYPE:
            retval =  new CardRenewalRequest();
            log.debug("Class of type CardRenewalRequest created");
            break;          
        case CardRenewalResponse.CLASS_TYPE:
            retval =  new CardRenewalResponse();
            log.debug("Class of type CardRenewalResponse created");
            break;          
		default:
			log.error("Error Class of type : " + classType + " not registred");
		}
		
		
		return retval;
	}
	
}
