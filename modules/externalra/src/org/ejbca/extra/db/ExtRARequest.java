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
 * Abstract base class of the ExtRA Sub Message request containing request information about the
 * user like dn, certificatetype ...
 * Also contains a requestId used to match the request with the given response.
 * 
 * All ExtRA request should inherit this class.
 * 
 * @author philip
 * @version $Id$
 */
public abstract class ExtRARequest extends UpgradeableDataHashMap implements ISubMessage {

	// Field constants
	protected static final String REQUESTID              = "REQUESTID";
	protected static final String USERNAME               = "USERNAME";
	protected static final String SUBJECTDN              = "SUBJECTDN";
	protected static final String SUBJECTALTNAME         = "SUBJECTALTNAME";
    protected static final String SUBJECTDIRATTRIBUTES   = "SUBJECTDIRATTRIBUTES";
	protected static final String EMAIL                  = "EMAIL";
	protected static final String ENDENTITYPROFLENAME    = "ENDENTITYPROFILENAME";	
	protected static final String CERTIFICATEPROFILENAME = "CERTIFICATEPROFILENAME";
	protected static final String CANAME                 = "CANAME";
	
	private static final long serialVersionUID = 1L;
	
	/**
	 * Default constructor that should be used.
	 */
	public ExtRARequest(long requestId, String username, String subjectDN, String subjectAltName, 
			            String email, String subjectDirectoryAttributes, 
                        String endEntityProfileName, String certificateProfileName,
			            String cAName){
        data.put(REQUESTID, Long.valueOf(requestId));
        data.put(USERNAME, username);
        data.put(SUBJECTDN, subjectDN);
        data.put(SUBJECTALTNAME, subjectAltName);
        data.put(EMAIL, email);
        data.put(SUBJECTDIRATTRIBUTES, subjectDirectoryAttributes);
        data.put(ENDENTITYPROFLENAME, endEntityProfileName);
        data.put(CERTIFICATEPROFILENAME, certificateProfileName);
        data.put(CANAME, cAName);
				
	}

	/**
	 * Constructor used when laoded from a persisted state
	 * 
	 */	
	public ExtRARequest(){}
	
	/**
	 * Returns the reqyest Id assiciated with this sub message.
	 */
	public long getRequestId(){
	   return ((Long) data.get(REQUESTID)).longValue();	
	}
	
	/**
	 * Returns the username used in request
	 * 
	 */
	public String getUsername(){
		return (String) data.get(USERNAME);
	}
	
	/**
	 * Returns the subjectDN used in request
	 */
	public String getSubjectDN(){
		return (String) data.get(SUBJECTDN);
	}

	/**
	 * Returns the subject Alt Name used in request
	 */
	public String getSubjectAltName(){
		return (String) data.get(SUBJECTALTNAME);
	}
	
	/**
	 * Returns the email used in request
	 */	
	public String getEmail(){
		return (String) data.get(EMAIL);
	}

    /**
     * Returns the subject direcotry attribites used in request
     */ 
    public String getSubjectDirectoryAttributes(){
        return (String) data.get(SUBJECTDIRATTRIBUTES);
    }
    
	/**
	 * Returns the name of the end entity profile used in request
	 */
	public String getEndEntityProfileName(){
		return (String) data.get(ENDENTITYPROFLENAME);
	}

	/**
	 * Returns the name of the certificate profile used in request
	 */
	public String getCertificateProfileName(){
		return (String) data.get(CERTIFICATEPROFILENAME);
	}
	
	/**
	 * Returns the name of the CA used in request
	 */	
	public String getCAName(){
		return (String) data.get(CANAME);
	}

	public void upgrade() {
		
		
	}

}
