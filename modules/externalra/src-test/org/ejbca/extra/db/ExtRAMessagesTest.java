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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.cesecore.util.CryptoProviderTools;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Makes sure that request and response classes are serialized properly.
 * 
 * @version $Id$
 */
public class ExtRAMessagesTest {
	
    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProvider();
    }
	
	@Test
	public void testUnencryptedSubMessages() throws Exception {
						
		SubMessages submessages = new SubMessages(null,null,null);
		submessages.addSubMessage(genExtRAPKCS10Request(1,"PKCS10REQ", "PKCS10"));
		submessages.addSubMessage(genExtRAPKCS12Request(2,"PKCS12REQ",false));
		submessages.addSubMessage(genExtRAKeyRecoveryRequest(3,"KEYRECREQ", true,null));
		submessages.addSubMessage(genExtRAPKCS10Response());
		submessages.addSubMessage(genExtRAPKCS12Response());
		
		assertFalse(submessages.isEncrypted());
		assertFalse(submessages.isSigned());
		
		// Test load and save unsecured data
		String result = submessages.save();		
		
		SubMessages loadedSubMessage = new SubMessages();
		loadedSubMessage.load(result,null,null);
		
		assertFalse(loadedSubMessage.isEncrypted());
		assertFalse(loadedSubMessage.isSigned());
		assertTrue(loadedSubMessage.getSubMessages().size() == 5);
		
        checkSubMessages(loadedSubMessage.getSubMessages());		
	}
	
    @Test
	public void testEncryptedSubMessages() throws Exception {
		
		SubMessages submessages = new SubMessages(null,null,Constants.getUserCert());
		submessages.addSubMessage(genExtRAPKCS10Request(1, "PKCS10REQ", "PKCS10"));
		submessages.addSubMessage(genExtRAPKCS12Request(2,"PKCS12REQ",false));
		submessages.addSubMessage(genExtRAKeyRecoveryRequest(3,"KEYRECREQ", true,null));
		submessages.addSubMessage(genExtRAPKCS10Response());
		submessages.addSubMessage(genExtRAPKCS12Response());
		
		assertTrue(submessages.isEncrypted());
		assertFalse(submessages.isSigned());
		
		// Test load and save unsecured data
		String result = submessages.save();
		
		SubMessages loadedSubMessage = new SubMessages();
		loadedSubMessage.load(result,Constants.getUserKey(),null);
		
		assertTrue(loadedSubMessage.isEncrypted());
		assertFalse(loadedSubMessage.isSigned());
		assertTrue(loadedSubMessage.getSubMessages().size() == 5);
		
        checkSubMessages(loadedSubMessage.getSubMessages());		
	}
	
    @Test
	public void testSignedSubMessages() throws Exception {
		
		SubMessages submessages = new SubMessages(Constants.getUserCert(),Constants.getUserKey(),null);
		submessages.addSubMessage(genExtRAPKCS10Request(1, "PKCS10REQ", "PKCS10"));
		submessages.addSubMessage(genExtRAPKCS12Request(2,"PKCS12REQ",false));
		submessages.addSubMessage(genExtRAKeyRecoveryRequest(3,"KEYRECREQ", true,null));
		submessages.addSubMessage(genExtRAPKCS10Response());
		submessages.addSubMessage(genExtRAPKCS12Response());
		
		assertFalse(submessages.isEncrypted());
		assertTrue(submessages.isSigned());
		
		// Test load and save unsecured data
		String result = submessages.save();
		
		
		SubMessages loadedSubMessage = new SubMessages();
		ArrayList<Certificate> cACerts = new ArrayList<Certificate>();
		cACerts.add(Constants.getRootCert());
		cACerts.add(Constants.getIntermediateCert());
		
		loadedSubMessage.load(result,null,cACerts);
		
		assertFalse(loadedSubMessage.isEncrypted());
		assertTrue(loadedSubMessage.isSigned());
		assertTrue(loadedSubMessage.getSubMessages().size() == 5);
		
        checkSubMessages(loadedSubMessage.getSubMessages());		
	}
	
    @Test
	public void testSignedAndEncryptedSubMessages() throws Exception {
		
		SubMessages submessages = new SubMessages(Constants.getUserCert(),Constants.getUserKey(),Constants.getUserCert());
		submessages.addSubMessage(genExtRAPKCS10Request(1,"PKCS10REQ", "PKCS10"));
		submessages.addSubMessage(genExtRAPKCS12Request(2, "PKCS12REQ", false));
		submessages.addSubMessage(genExtRAKeyRecoveryRequest(3,"KEYRECREQ", true,null));
		submessages.addSubMessage(genExtRAPKCS10Response());
		submessages.addSubMessage(genExtRAPKCS12Response());
		
		assertTrue(submessages.isEncrypted());
		assertTrue(submessages.isSigned());
		
		// Test load and save unsecured data
		String result = submessages.save();
		
		SubMessages loadedSubMessage = new SubMessages();
		ArrayList<Certificate> cACerts = new ArrayList<Certificate>();
		cACerts.add(Constants.getRootCert());
		cACerts.add(Constants.getIntermediateCert());
		
		loadedSubMessage.load(result,Constants.getUserKey(),cACerts);
		
		assertTrue(loadedSubMessage.isEncrypted());
		assertTrue(loadedSubMessage.isSigned());
		assertTrue(loadedSubMessage.getSubMessages().size() == 5);
		
        checkSubMessages(loadedSubMessage.getSubMessages());		
	}
	
	
    // Not test methods below
	public static PKCS10Request genExtRAPKCS10Request(long requestId, String username, String pkcs10, boolean createUser){
		PKCS10Request req = new PKCS10Request(requestId,username, "CN=PKCS10REQ", "RFC822NAME=PKCS10Request@test.com",
				                           "PKCS10Request@test.com", null, "EMPTY", "ENDUSER", 
				                           "ManagementCA",pkcs10);
		req.setCreateOrEditUser(createUser);
		return req;
		}
	public static PKCS10Request genExtRAPKCS10Request(long requestId, String username, String pkcs10){
	   return genExtRAPKCS10Request(requestId, username, pkcs10, true);
	}
	public static EditUserRequest genExtRAPKCS10UserRequest(long requestId, String username, String password){
		   return new EditUserRequest(requestId,username, "CN=PKCS10REQ", "RFC822NAME=PKCS10Request@test.com",
				                           "PKCS10Request@test.com", null, "EMPTY", "ENDUSER", 
				                           "ManagementCA",password,10, 1, "USERGENERATED", null);
	    }
	
	public static PKCS12Request genExtRAPKCS12Request(long requestId, String username, boolean store){
	   return new PKCS12Request(requestId,username, "CN=PKCS12REQ", "RFC822NAME=PKCS12Request@test.com",
			                           "PKCS12Request@test.com", null, "EMPTY", "ENDUSER", 
			                           "ManagementCA","foo123",PKCS12Request.KEYALG_RSA, "1024", store);
    }
	
	public static EditUserRequest genExtRAEditUserRequest(long requestId, String username){
		   return new EditUserRequest(requestId,username, "CN=PKCS12REQ", "RFC822NAME=PKCS12Request@test.com",
				                           "PKCS12Request@test.com", null, "EMPTY", "ENDUSER", 
				                           "ManagementCA","foo123",10, 1, "USERGENERATED", null);
	    }
	
	
	public static KeyRecoveryRequest genExtRAKeyRecoveryRequest(long requestId, String username, boolean orgCert, X509Certificate cert){
		if(cert == null){
		      return new KeyRecoveryRequest(requestId, username, "KEYRECPWD", 
                      "CN=ManagementCA,O=EJBCA Sample,C=SE", 
                      new BigInteger("1"));			
		}
		if(orgCert){
		      return new KeyRecoveryRequest(requestId, username, "foo123", 
                      cert.getIssuerDN().toString(), 
                      cert.getSerialNumber());		
		}else{
		      return new KeyRecoveryRequest(requestId,username, 
		    		  "CN=KEYRECREQ", "RFC822NAME=KEYRECRequest@test.com",
                      "KEYRECRequest@test.com", null, "EMPTY", "ENDUSER", 
                      "ManagementCA","foo123",
                      cert.getIssuerDN().toString(), 
                      cert.getSerialNumber());	
		}
	}
	
	static PKCS10Response genExtRAPKCS10Response() throws Exception {
	  return new PKCS10Response(4,true, "PKCS10RESFAILINFO", Constants.getUserCert(), null);
    }
	
	static PKCS12Response genExtRAPKCS12Response() throws Exception{
	  return new PKCS12Response(5,true, "PKCS12RESFAILINFO", Constants.getUserKeyStore(),"foo123");
	}
	
	static void checkSubMessages(List<ISubMessage> submessages) throws Exception{
	  Iterator<ISubMessage> iter = submessages.iterator();
	  while(iter.hasNext()){
		ISubMessage submessage = (ISubMessage) iter.next();
		if(submessage instanceof PKCS10Request){
			checkExtRAPKCS10Request((PKCS10Request) submessage);			
		}
		if(submessage instanceof PKCS12Request){
			checkExtRAPKCS12Request((PKCS12Request) submessage);			
		}
		if(submessage instanceof KeyRecoveryRequest){
		     checkExtRAKeyRecoveryRequest((KeyRecoveryRequest) submessage);				
		}
		if(submessage instanceof PKCS10Response){
			checkExtRAPKCS10Response((PKCS10Response) submessage);
		}
		if(submessage instanceof PKCS12Response){
			checkExtRAPKCS12Response((PKCS12Response) submessage);
		}
		
	  }
	  
	}
	
	static void checkExtRAPKCS10Request(PKCS10Request submessage) {
		assertTrue(submessage.getRequestId() == 1);
		assertTrue(submessage.getUsername().equals("PKCS10REQ"));
		assertTrue(submessage.getSubjectDN().equals("CN=PKCS10REQ"));
		assertTrue(submessage.getSubjectAltName().equals("RFC822NAME=PKCS10Request@test.com"));
		assertTrue(submessage.getEmail().equals("PKCS10Request@test.com"));
		assertTrue(submessage.getEndEntityProfileName().equals("EMPTY"));
		assertTrue(submessage.getCertificateProfileName().equals("ENDUSER"));
		assertTrue(submessage.getCAName().equals("ManagementCA"));	
		assertTrue(submessage.getPKCS10().equals("PKCS10"));
	}

	static void checkExtRAPKCS12Request(PKCS12Request submessage) {
		assertTrue(submessage.getRequestId() == 2);
		assertTrue(submessage.getUsername().equals("PKCS12REQ"));
		assertTrue(submessage.getSubjectDN().equals("CN=PKCS12REQ"));
		assertTrue(submessage.getSubjectAltName().equals("RFC822NAME=PKCS12Request@test.com"));
		assertTrue(submessage.getEmail().equals("PKCS12Request@test.com"));
		assertTrue(submessage.getEndEntityProfileName().equals("EMPTY"));
		assertTrue(submessage.getCertificateProfileName().equals("ENDUSER"));
		assertTrue(submessage.getCAName().equals("ManagementCA"));
		assertTrue(submessage.getPassword().equals("foo123"));
		assertTrue(submessage.getKeyAlg() == PKCS12Request.KEYALG_RSA);
		assertTrue(submessage.getKeySpec().equals("1024"));
		assertFalse(submessage.getStoreKeys());
	}

	static void checkExtRAKeyRecoveryRequest(KeyRecoveryRequest submessage) {
        assertTrue(submessage.getRequestId() == 3);
        assertTrue(submessage.getPassword().equals("KEYRECPWD"));
        assertTrue(submessage.getReUseCertificate() == true);
        assertTrue(submessage.getIssuerDN().equals("CN=ManagementCA,O=EJBCA Sample,C=SE"));
        assertTrue(submessage.getCertificateSN().equals(new BigInteger("1")));
	}

	static void checkExtRAPKCS10Response(PKCS10Response submessage) throws Exception{
         assertTrue(submessage.getRequestId() == 4);
         assertTrue(submessage.isSuccessful() == true);
         assertTrue(submessage.getFailInfo().equals("PKCS10RESFAILINFO"));
         assertTrue(submessage.getCertificate().getSubjectDN().toString().equals(Constants.getUserCert().getSubjectDN().toString()));
	}

	static void checkExtRAPKCS12Response(PKCS12Response submessage) throws Exception {
        assertTrue(submessage.getRequestId() == 5);
        assertTrue(submessage.isSuccessful() == true);
        assertTrue(submessage.getFailInfo().equals("PKCS12RESFAILINFO"));
        assertTrue(((X509Certificate) submessage.getKeyStore("foo123").getCertificate("TEST")).getSubjectDN().toString()
        		   .equals(Constants.getUserCert().getSubjectDN().toString()));
	}
}
