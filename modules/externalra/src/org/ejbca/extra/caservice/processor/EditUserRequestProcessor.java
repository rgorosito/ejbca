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
package org.ejbca.extra.caservice.processor;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.model.SecConst;
import org.ejbca.extra.db.EditUserRequest;
import org.ejbca.extra.db.ExtRARequest;
import org.ejbca.extra.db.ExtRAResponse;
import org.ejbca.extra.db.ISubMessage;

/**
 * 
 * @author tomas
 * @version $Id$
 */
public class EditUserRequestProcessor extends MessageProcessor implements ISubMessageProcessor {
    private static final Logger log = Logger.getLogger(EditUserRequestProcessor.class);

    public ISubMessage process(AuthenticationToken admin, ISubMessage submessage, String errormessage) {
		if(errormessage == null){
			return processExtRAEditUserRequest(admin, (EditUserRequest) submessage);
		}else{
			return new ExtRAResponse(((ExtRARequest) submessage).getRequestId(), false, errormessage);
		}
    }

    private ISubMessage processExtRAEditUserRequest(AuthenticationToken admin, EditUserRequest submessage) {
		log.debug("Processing ExtRAEditUserRequest");
		ExtRAResponse retval = null;
        EndEntityInformation userdata = null;
		try{
            userdata = generateUserDataVO(admin, submessage);
            userdata.setPassword(submessage.getPassword());			   
			userdata.setType(submessage.getType());
			userdata.setTokenType(getTokenTypeId(submessage.getTokenName()));
			userdata.setHardTokenIssuerId(getHardTokenIssuerId(submessage.getHardTokenIssuerName()));
	        storeUserData(admin, userdata, false, submessage.getStatus());
	        retval = new ExtRAResponse(submessage.getRequestId(),true,null);
		}catch(Exception e){
			log.error("Error processing ExtRAEditUserRequest : ", e);
            if (userdata != null) {
                try {
                    storeUserData(admin, userdata, false, EndEntityConstants.STATUS_FAILED);                    
                } catch (Exception ignore) {/*ignore*/}
            }
			retval = new ExtRAResponse(submessage.getRequestId(),false,e.getMessage());
		}
		return retval;
	}
    
	private static final String[] AVAILABLESOFTTOKENNAMES = {EditUserRequest.SOFTTOKENNAME_USERGENERATED, 
        EditUserRequest.SOFTTOKENNAME_P12, 
        EditUserRequest.SOFTTOKENNAME_JKS, 
        EditUserRequest.SOFTTOKENNAME_PEM };

	private static final int[] AVAILABLESOFTTOKENIDS = {SecConst.TOKEN_SOFT_BROWSERGEN,
		SecConst.TOKEN_SOFT_P12, 
		SecConst.TOKEN_SOFT_JKS, 
		SecConst.TOKEN_SOFT_PEM};	

	private int getTokenTypeId(String tokenName) throws EjbcaException, ClassCastException {
		for(int i=0; i< AVAILABLESOFTTOKENNAMES.length ; i++){
			if(tokenName.equalsIgnoreCase(AVAILABLESOFTTOKENNAMES[i])){
				return AVAILABLESOFTTOKENIDS[i];
			}
		}
		int retval = hardTokenSession.getHardTokenProfileId(tokenName);
		if(retval == 0){
			throw new EjbcaException("Error Token with name " + tokenName + " does not exist.");
		}
		return retval;
	}

	private int getHardTokenIssuerId(String hardTokenIssuerName) {
		return hardTokenSession.getHardTokenIssuerId(hardTokenIssuerName);
	}
}
