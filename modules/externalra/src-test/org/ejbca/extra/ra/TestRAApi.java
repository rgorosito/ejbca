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
package org.ejbca.extra.ra;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertStore;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

import javax.persistence.Persistence;

import junit.framework.TestCase;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.ejbca.core.model.ca.catoken.CATokenConstants;
import org.ejbca.extra.db.CardRenewalRequest;
import org.ejbca.extra.db.Constants;
import org.ejbca.extra.db.ExtRAResponse;
import org.ejbca.extra.db.Message;
import org.ejbca.extra.db.MessageHome;
import org.ejbca.extra.db.PKCS10Response;
import org.ejbca.extra.db.PKCS12Response;
import org.ejbca.extra.db.RevocationRequest;
import org.ejbca.extra.db.SubMessages;
import org.ejbca.extra.db.TestExtRAMessages;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.keystore.KeyTools;


/**
 * JUnit test used to test the ExtRA API in a similar environment as used in production. Will connect to a RA message database and
 * sent messages that should be pulled and processed by the CA.
 * 
 * The test makes a full scale tests of sending PKCS10 and PKCS12 request to the CA and waits
 * for proper responses. May take some time and check the server log for errors. Revocation of
 * some of the generated certificates is also tested.
 * 
 * The following requirements should be set in order to run the tests.
 * - Properly configured database
 * - External RA CA-service worker installed on EJBCA machine
 * 
 * @author philip
 * @version $Id: TestRAApi.java,v 1.11 2008-04-01 05:10:32 anatom Exp $
 */

public class TestRAApi extends TestCase {
	
	protected void setUp() throws Exception {
		super.setUp();
		CertTools.installBCProvider();			
	}
	
	private static X509Certificate firstCertificate = null;
	private static X509Certificate secondCertificate = null;
	
	private static MessageHome msghome = new MessageHome(Persistence.createEntityManagerFactory("external-ra-test"), MessageHome.MESSAGETYPE_EXTRA, true);
	
	public void test01GenerateSimplePKCS10Request() throws Exception {

		SubMessages smgs = new SubMessages(null,null,null);
		smgs.addSubMessage(TestExtRAMessages.genExtRAPKCS10Request(100,"SimplePKCS10Test1", Constants.pkcs10_1));
		smgs.addSubMessage(TestExtRAMessages.genExtRAPKCS10Request(101,"SimplePKCS10Test1", Constants.pkcs10_2));
		
		msghome.create("SimplePKCS10Test1", smgs);
		
        Message msg = waitForUser("SimplePKCS10Test1");
		
		assertNotNull("No response.", msg);
		
		SubMessages submessagesresp = msg.getSubMessages(null,null,null);
		
		assertTrue(submessagesresp.getSubMessages().size() == 2);
		
		Iterator iter =  submessagesresp.getSubMessages().iterator();
		PKCS10Response resp = (PKCS10Response) iter.next();
		assertTrue(resp.getRequestId() == 100);
		assertTrue(resp.isSuccessful() == true);		
		assertTrue(resp.getCertificate().getSubjectDN().toString().equals("CN=PKCS10REQ"));
		firstCertificate = resp.getCertificate();
		assertNotNull(firstCertificate);
		// Check the pkcs7 response
		byte[] pkcs7 = resp.getCertificateAsPKCS7();
		assertNotNull(pkcs7);
        CMSSignedData s = new CMSSignedData(pkcs7);
        // The signer, i.e. the CA, check it's the right CA
        SignerInformationStore signers = s.getSignerInfos();
        Collection col = signers.getSigners();
        assertTrue(col.size() > 0);
        Iterator siter = col.iterator();
        SignerInformation signerInfo = (SignerInformation)siter.next();
        SignerId sinfo = signerInfo.getSID();
        // Check that the signer is the expected CA
        assertEquals(CertTools.stringToBCDNString(firstCertificate.getIssuerDN().getName()), CertTools.stringToBCDNString(sinfo.getIssuerAsString()));
        CertStore certstore = s.getCertificatesAndCRLs("Collection","BC");
        Collection certs = certstore.getCertificates(null);
        assertEquals(certs.size(), 2);                	
        Iterator it = certs.iterator();
        boolean found = false;
        while (it.hasNext()) {
            X509Certificate retcert = (X509Certificate)it.next();
            if (retcert.getSubjectDN().equals(firstCertificate.getSubjectDN())) {
            	found = true;
            }
        }
        assertTrue(found);

	    resp = (PKCS10Response) iter.next();
		assertTrue(resp.getRequestId() == 101);
		assertTrue(resp.isSuccessful() == true);		
		assertTrue(resp.getCertificate().getSubjectDN().toString().equals("CN=PKCS10REQ"));
		secondCertificate = resp.getCertificate();
		assertNotNull(secondCertificate);
		pkcs7 = resp.getCertificateAsPKCS7();
		assertNotNull(pkcs7);
		
		// TODO: test with createUser = false
	
	}
	
	public void test02GenerateSimplePKCS10RequestNoCreateUser() throws Exception {

		// First test with a user that does not exist or has status generated, when the user it not created the request will fail
		SubMessages smgs = new SubMessages(null,null,null);
		smgs.addSubMessage(TestExtRAMessages.genExtRAPKCS10Request(100,"SimplePKCS10Test1NoAdd", Constants.pkcs10_1, false));
		msghome.create("SimplePKCS10Test1NoAdd", smgs);
        Message msg = waitForUser("SimplePKCS10Test1NoAdd");
		assertNotNull("No response", msg);
		SubMessages submessagesresp = msg.getSubMessages(null,null,null);
		assertTrue(submessagesresp.getSubMessages().size() == 1);		
		Iterator iter =  submessagesresp.getSubMessages().iterator();
		PKCS10Response resp = (PKCS10Response) iter.next();
		assertTrue(resp.getRequestId() == 100);
		assertTrue(resp.isSuccessful() == false);
		
		// if we create the user first, with correct status, the request should be ok
		smgs = new SubMessages(null,null,null);
		smgs.addSubMessage(TestExtRAMessages.genExtRAPKCS10UserRequest(101,"SimplePKCS10Test1NoAdd", "foo123"));
		msghome.create("SimplePKCS10Test1NoAdd", smgs);		
        msg = waitForUser("SimplePKCS10Test1NoAdd");
		assertNotNull(msg);
		submessagesresp = msg.getSubMessages(null,null,null);
		assertTrue("Number of submessages " + submessagesresp.getSubMessages().size(), submessagesresp.getSubMessages().size() == 1);
		ExtRAResponse editresp = (ExtRAResponse) submessagesresp.getSubMessages().iterator().next();
		assertTrue("Wrong Request ID" + editresp.getRequestId(), editresp.getRequestId() == 101);
		assertTrue("External RA CA Service was not successful.", editresp.isSuccessful() == true);

		// Create a new request, now it should be ok
		smgs = new SubMessages(null,null,null);
		smgs.addSubMessage(TestExtRAMessages.genExtRAPKCS10Request(102,"SimplePKCS10Test1NoAdd", Constants.pkcs10_1, false));
		msghome.create("SimplePKCS10Test1NoAdd", smgs);		
        msg = waitForUser("SimplePKCS10Test1NoAdd");
		assertNotNull(msg);
		submessagesresp = msg.getSubMessages(null,null,null);
		assertTrue(submessagesresp.getSubMessages().size() == 1);
		iter =  submessagesresp.getSubMessages().iterator();
		resp = (PKCS10Response) iter.next();
		assertTrue(resp.getRequestId() == 102);
		assertTrue(resp.isSuccessful() == true);		
		assertTrue(resp.getCertificate().getSubjectDN().toString().equals("CN=PKCS10REQ"));
		firstCertificate = resp.getCertificate();
		assertNotNull(firstCertificate);
		// Check the pkcs7 response
		byte[] pkcs7 = resp.getCertificateAsPKCS7();
		assertNotNull(pkcs7);
        CMSSignedData s = new CMSSignedData(pkcs7);
        // The signer, i.e. the CA, check it's the right CA
        SignerInformationStore signers = s.getSignerInfos();
        Collection col = signers.getSigners();
        assertTrue(col.size() > 0);
        Iterator siter = col.iterator();
        SignerInformation signerInfo = (SignerInformation)siter.next();
        SignerId sinfo = signerInfo.getSID();
        // Check that the signer is the expected CA
        assertEquals(CertTools.stringToBCDNString(firstCertificate.getIssuerDN().getName()), CertTools.stringToBCDNString(sinfo.getIssuerAsString()));
        CertStore certstore = s.getCertificatesAndCRLs("Collection","BC");
        Collection certs = certstore.getCertificates(null);
        assertEquals(certs.size(), 2);                	
        Iterator it = certs.iterator();
        boolean found = false;
        while (it.hasNext()) {
            X509Certificate retcert = (X509Certificate)it.next();
            if (retcert.getSubjectDN().equals(firstCertificate.getSubjectDN())) {
            	found = true;
            }
        }
        assertTrue(found);

	}

	
	public void test03GenerateSimplePKCS12Request() throws Exception {		
		SubMessages smgs = new SubMessages(null,null,null);
		smgs.addSubMessage(TestExtRAMessages.genExtRAPKCS12Request(200,"SimplePKCS12Test1", false));
		
		msghome.create("SimplePKCS12Test1", smgs);
		
        Message msg = waitForUser("SimplePKCS12Test1");
		assertNotNull("No response.", msg);
		
		SubMessages submessagesresp = msg.getSubMessages(null,null,null);
		
		assertTrue(submessagesresp.getSubMessages().size() == 1);
		
		PKCS12Response resp = (PKCS12Response) submessagesresp.getSubMessages().iterator().next();
		assertTrue(resp.getRequestId() == 200);
		assertTrue(resp.isSuccessful() == true);
		assertNotNull(resp.getKeyStore("foo123"));
		KeyStore ks = resp.getKeyStore("foo123");
		String alias = ks.aliases().nextElement();
		
		assertTrue(((X509Certificate) resp.getKeyStore("foo123").getCertificate(alias)).getSubjectDN().toString().equals("CN=PKCS12REQ"));
			
		
		
	}
	
	/** This test requires that keyrecovery is enabled in the EJBCA Admin-GUI */
	public void test04GenerateSimpleKeyRecoveryRequest() throws Exception {
		// First generate keystore
		SubMessages smgs = new SubMessages(null,null,null);
		smgs.addSubMessage(TestExtRAMessages.genExtRAPKCS12Request(300,"SimpleKeyRecTest", true));
		
		msghome.create("SimpleKeyRecTest", smgs);
		
        Message msg = waitForUser("SimpleKeyRecTest");
		assertNotNull("No response.", msg);
		
		SubMessages submessagesresp = msg.getSubMessages(null,null,null);
		
		assertTrue(submessagesresp.getSubMessages().size() == 1);
		
		PKCS12Response resp = (PKCS12Response) submessagesresp.getSubMessages().iterator().next();
		assertTrue(resp.getRequestId() == 300);
		assertTrue(resp.isSuccessful() == true);
		assertNotNull(resp.getKeyStore("foo123"));
		//KeyStore ks = resp.getKeyStore("foo123");		
		
		X509Certificate orgCert = (X509Certificate) resp.getKeyStore("foo123").getCertificate("PKCS12REQ");
		
		assertTrue(orgCert.getSubjectDN().toString().equals("CN=PKCS12REQ"));
		
		// Generate Key Recovery request with original cert.
		
		smgs = new SubMessages(null,null,null);
		smgs.addSubMessage(TestExtRAMessages.genExtRAKeyRecoveryRequest(301,"SimpleKeyRecTest",true,orgCert));
		
		msghome.create("SimpleKeyRecTest", smgs);
		
        msg = waitForUser("SimpleKeyRecTest");
		
		assertNotNull(msg);
		
		submessagesresp = msg.getSubMessages(null,null,null);
		
		assertTrue(submessagesresp.getSubMessages().size() == 1);
		
		resp = (PKCS12Response) submessagesresp.getSubMessages().iterator().next();
		assertEquals(301, resp.getRequestId());
		assertTrue(resp.isSuccessful());
		
		X509Certificate keyRecCert = (X509Certificate) resp.getKeyStore("foo123").getCertificate("PKCS12REQ");
        assertTrue(keyRecCert.getSerialNumber().equals(orgCert.getSerialNumber()));
        
        // Generate Key Recovery Request with new cert
        
		smgs = new SubMessages(null,null,null);
		smgs.addSubMessage(TestExtRAMessages.genExtRAKeyRecoveryRequest(302,"SimpleKeyRecTest",false,orgCert));
		
		msghome.create("SimpleKeyRecTest", smgs);
		
        msg = waitForUser("SimpleKeyRecTest");
		
		assertNotNull(msg);
		
		submessagesresp = msg.getSubMessages(null,null,null);
		
		assertTrue(submessagesresp.getSubMessages().size() == 1);
		
		resp = (PKCS12Response) submessagesresp.getSubMessages().iterator().next();
		assertTrue(resp.getRequestId() == 302);
		assertTrue(resp.isSuccessful() == true);
		
		keyRecCert = (X509Certificate) resp.getKeyStore("foo123").getCertificate("KEYRECREQ");
        assertFalse(keyRecCert.getSerialNumber().equals(orgCert.getSerialNumber()));
	}
	
	public void test05GenerateSimpleRevokationRequest() throws Exception {
		// revoke first certificate
		SubMessages smgs = new SubMessages(null,null,null);
		assertNotNull("Missing certificate from previous test.", firstCertificate);
		smgs.addSubMessage(new RevocationRequest(10, CertTools.getIssuerDN(firstCertificate), firstCertificate.getSerialNumber(), RevocationRequest.REVOKATION_REASON_UNSPECIFIED));
		
		msghome.create("SimpleRevocationTest", smgs);
		
        Message msg = waitForUser("SimpleRevocationTest");
		assertNotNull("No response.", msg);
		
		SubMessages submessagesresp = msg.getSubMessages(null,null,null);
		
		assertTrue("Number of submessages " + submessagesresp.getSubMessages().size(), submessagesresp.getSubMessages().size() == 1);
		
		ExtRAResponse resp = (ExtRAResponse) submessagesresp.getSubMessages().iterator().next();
		assertTrue("Wrong Request ID" + resp.getRequestId(), resp.getRequestId() == 10);
		assertTrue(resp.isSuccessful() == true);
	
		// revoke second certificate	
		SubMessages smgs2 = new SubMessages(null,null,null);
		assertNotNull("Missing certificate from previous test.", secondCertificate);
		smgs2.addSubMessage(new RevocationRequest(6, CertTools.getIssuerDN(secondCertificate), secondCertificate.getSerialNumber(), RevocationRequest.REVOKATION_REASON_UNSPECIFIED));
		
		msghome.create("SimpleRevocationTest", smgs2);
		
        Message msg2 = waitForUser("SimpleRevocationTest");
		
		assertNotNull(msg2);
		
		SubMessages submessagesresp2 = msg2.getSubMessages(null,null,null);
		
		assertTrue("Number of submessages " + submessagesresp2.getSubMessages().size() ,  submessagesresp2.getSubMessages().size() == 1);
		
		ExtRAResponse resp2 = (ExtRAResponse) submessagesresp2.getSubMessages().iterator().next();
		assertTrue(resp2.getRequestId() == 6);
		assertTrue(resp2.isSuccessful() == true); 
		
		// try to revoke nonexisting certificate	
		SubMessages smgs3 = new SubMessages(null,null,null);
		smgs3.addSubMessage(new RevocationRequest(7, CertTools.getIssuerDN(secondCertificate), new BigInteger("1234"), RevocationRequest.REVOKATION_REASON_UNSPECIFIED));
		
		msghome.create("SimpleRevocationTest", smgs3);
		
        Message msg3 = waitForUser("SimpleRevocationTest");
		
		assertNotNull(msg3);
		
		SubMessages submessagesresp3 = msg3.getSubMessages(null,null,null);
		
		assertTrue(submessagesresp3.getSubMessages().size() == 1);
		
		ExtRAResponse resp3 = (ExtRAResponse) submessagesresp3.getSubMessages().iterator().next();
		assertTrue(resp3.getRequestId() == 7);
		assertTrue(resp3.isSuccessful() == false); 
        
		// try to revoke a users all certificates
		SubMessages smgs4 = new SubMessages(null,null,null);
		smgs4.addSubMessage(new RevocationRequest(8, CertTools.getIssuerDN(secondCertificate), secondCertificate.getSerialNumber(), RevocationRequest.REVOKATION_REASON_UNSPECIFIED, false, true));
		
		msghome.create("SimpleRevocationTest", smgs4);
		
        Message msg4 = waitForUser("SimpleRevocationTest");
		
		assertNotNull(msg4);
		
		SubMessages submessagesresp4 = msg4.getSubMessages(null,null,null);
		
		assertTrue(submessagesresp4.getSubMessages().size() == 1);
		
		ExtRAResponse resp4 = (ExtRAResponse) submessagesresp4.getSubMessages().iterator().next();
		assertTrue(resp4.getRequestId() == 8);
		assertTrue(resp4.isSuccessful() == true);
		
		// try to revoke a users all certificates by giving the username
		SubMessages smgs5 = new SubMessages(null,null,null);
		smgs5.addSubMessage(new RevocationRequest(9, "SimplePKCS10Test1", RevocationRequest.REVOKATION_REASON_UNSPECIFIED, false));
		
		msghome.create("SimpleRevocationTest", smgs5);
		
        Message msg5 = waitForUser("SimpleRevocationTest");
		
		assertNotNull(msg5);
		
		SubMessages submessagesresp5 = msg5.getSubMessages(null,null,null);
		
		assertTrue(submessagesresp5.getSubMessages().size() == 1);
		
		ExtRAResponse resp5 = (ExtRAResponse) submessagesresp5.getSubMessages().iterator().next();
		assertTrue(resp5.getRequestId() == 9);
		assertTrue(resp5.isSuccessful() == true);
		
		// Try some error cases
        // First a message with null as parameters
		SubMessages smgs6 = new SubMessages(null,null,null);
		smgs6.addSubMessage(new RevocationRequest(10, null, RevocationRequest.REVOKATION_REASON_UNSPECIFIED, false));		
		msghome.create("SimpleRevocationTest", smgs6);
        Message msg6 = waitForUser("SimpleRevocationTest");
		assertNotNull(msg6);
		SubMessages submessagesresp6 = msg6.getSubMessages(null,null,null);
		assertTrue(submessagesresp6.getSubMessages().size() == 1);
		ExtRAResponse resp6 = (ExtRAResponse) submessagesresp6.getSubMessages().iterator().next();
		assertTrue(resp6.getRequestId() == 10);
		assertTrue(resp6.isSuccessful() == false);
        assertEquals(resp6.getFailInfo(), "Either username or issuer/serno is required");
        
        // Then a message with a suername that does not exist
        SubMessages smgs7 = new SubMessages(null,null,null);
        smgs7.addSubMessage(new RevocationRequest(11, "184hjeyyydvv88q", RevocationRequest.REVOKATION_REASON_UNSPECIFIED, false));     
        msghome.create("SimpleRevocationTest", smgs7);
        Message msg7 = waitForUser("SimpleRevocationTest");
        assertNotNull(msg7);
        SubMessages submessagesresp7 = msg7.getSubMessages(null,null,null);
        assertTrue(submessagesresp7.getSubMessages().size() == 1);
        ExtRAResponse resp7 = (ExtRAResponse) submessagesresp7.getSubMessages().iterator().next();
        assertTrue(resp7.getRequestId() == 11);
        assertTrue(resp7.isSuccessful() == false);
        assertEquals(resp7.getFailInfo(), "User not found from username: username=184hjeyyydvv88q");

        // Then a message with a issuer/serno that does not exist
        SubMessages smgs8 = new SubMessages(null,null,null);
        smgs8.addSubMessage(new RevocationRequest(12, "CN=ffo558444,O=338qqwaa,C=qq", new BigInteger("123"), RevocationRequest.REVOKATION_REASON_UNSPECIFIED, false, false));     
        msghome.create("SimpleRevocationTest", smgs8);
        Message msg8 = waitForUser("SimpleRevocationTest");
        assertNotNull(msg8);
        SubMessages submessagesresp8 = msg8.getSubMessages(null,null,null);
        assertTrue(submessagesresp8.getSubMessages().size() == 1);
        ExtRAResponse resp8 = (ExtRAResponse) submessagesresp8.getSubMessages().iterator().next();
        assertTrue(resp8.getRequestId() == 12);
        assertTrue(resp8.isSuccessful() == false);
        assertEquals(resp8.getFailInfo(), "User not found from issuer/serno: issuer='CN=ffo558444,O=338qqwaa,C=qq', serno=123");
	}
	
	public void test06GenerateSimpleEditUserRequest() throws Exception {
		
		// edit a user
		SubMessages smgs = new SubMessages(null,null,null);
		smgs.addSubMessage(TestExtRAMessages.genExtRAEditUserRequest(11,"SimpleEditUserTest"));
		
		msghome.create("SimpleEditUserTest", smgs);
		
        Message msg = waitForUser("SimpleEditUserTest");
		assertNotNull("No response.", msg);
		
		SubMessages submessagesresp = msg.getSubMessages(null,null,null);
		
		assertTrue("Number of submessages " + submessagesresp.getSubMessages().size(), submessagesresp.getSubMessages().size() == 1);
		
		ExtRAResponse resp = (ExtRAResponse) submessagesresp.getSubMessages().iterator().next();
		assertTrue("Wrong Request ID" + resp.getRequestId(), resp.getRequestId() == 11);
		assertTrue(resp.isSuccessful() == true);
	}	
	
	public void test07GenerateComplexRequest() throws Exception {
		
		SubMessages smgs = new SubMessages(null,null,null);
		smgs.addSubMessage(TestExtRAMessages.genExtRAPKCS10Request(1,"ComplexReq", Constants.pkcs10_1));
		smgs.addSubMessage(TestExtRAMessages.genExtRAPKCS12Request(2,"ComplexReq", false));
		smgs.addSubMessage(TestExtRAMessages.genExtRAPKCS12Request(3,"ComplexReq", false));
		
		msghome.create("COMPLEXREQ_1", smgs);
		
        Message msg = waitForUser("COMPLEXREQ_1");
		assertNotNull("No response.", msg);
		
		SubMessages submessagesresp = msg.getSubMessages(null,null,null);
		
		assertTrue(submessagesresp.getSubMessages().size() == 3);
		
		
		Iterator iter = submessagesresp.getSubMessages().iterator();
		PKCS10Response resp1 = (PKCS10Response) iter.next();
		PKCS12Response resp2 = (PKCS12Response) iter.next();
		PKCS12Response resp3 = (PKCS12Response) iter.next();
		assertTrue(resp1.getRequestId() == 1);
		assertTrue(resp1.isSuccessful() == true);
		assertTrue(resp2.getRequestId() == 2);
		assertTrue(resp2.isSuccessful() == true);
		assertTrue(resp3.getRequestId() == 3);
		assertTrue(resp3.isSuccessful() == true);
	}
	
	public void test08GenerateLotsOfRequest() throws Exception {
		
		int numberOfRequests = 10;
		
		for(int i=0; i< numberOfRequests; i++){
		  SubMessages smgs = new SubMessages(null,null,null);
		  smgs.addSubMessage(TestExtRAMessages.genExtRAPKCS10Request(1,"LotsOfReq" + i, Constants.pkcs10_1));		
		  msghome.create("LotsOfReq" + i, smgs);
		}

		Message[] resps = new Message[numberOfRequests];
		for(int i=0; i < numberOfRequests; i++){
			resps[i] = waitForUser("LotsOfReq"+i);
			assertNotNull("No response.", resps[i]);
			SubMessages submessagesresp = resps[i].getSubMessages(null,null,null);
			PKCS10Response resp = (PKCS10Response) submessagesresp.getSubMessages().iterator().next();
			assertTrue(resp.isSuccessful() == true);
		}								
	} 
	
	public void test09GenerateSimpleCardRenewalRequest() throws Exception {
		
		// First fail message
		SubMessages smgs = new SubMessages(null,null,null);
		assertNotNull("Missing certificate from previous test.", firstCertificate);
		String cert1 = new String(Base64.encode(firstCertificate.getEncoded()));
		assertNotNull("Missing certificate from previous test.", secondCertificate);
        String cert2 = new String(Base64.encode(secondCertificate.getEncoded()));
		smgs.addSubMessage(new CardRenewalRequest(10, cert1, cert1, null, null));
		msghome.create("SimpleCardRenewalTest", smgs);
        Message msg = waitForUser("SimpleCardRenewalTest");
		assertNotNull("No response.", msg);
		SubMessages submessagesresp = msg.getSubMessages(null,null,null);
		assertTrue("Number of submessages " + submessagesresp.getSubMessages().size(), submessagesresp.getSubMessages().size() == 1);
		ExtRAResponse resp = (ExtRAResponse) submessagesresp.getSubMessages().iterator().next();
		assertTrue("Wrong Request ID" + resp.getRequestId(), resp.getRequestId() == 10);
		assertTrue(resp.isSuccessful() == false);
        assertEquals(resp.getFailInfo(), "An authentication cert, a signature cert, an authentication request and a signature request are required");

        // Second fail message
		smgs = new SubMessages(null,null,null);
		smgs.addSubMessage(new CardRenewalRequest(11, null, null, Constants.pkcs10_1, Constants.pkcs10_2));
		msghome.create("SimpleCardRenewalTest", smgs);
        msg = waitForUser("SimpleCardRenewalTest");
		assertNotNull(msg);
		submessagesresp = msg.getSubMessages(null,null,null);
		assertTrue("Number of submessages " + submessagesresp.getSubMessages().size(), submessagesresp.getSubMessages().size() == 1);
		resp = (ExtRAResponse) submessagesresp.getSubMessages().iterator().next();
		assertTrue("Wrong Request ID" + resp.getRequestId(), resp.getRequestId() == 11);
		assertTrue(resp.isSuccessful() == false);
        assertEquals(resp.getFailInfo(), "An authentication cert, a signature cert, an authentication request and a signature request are required");

        // Third fail message
		smgs = new SubMessages(null,null,null);
		smgs.addSubMessage(new CardRenewalRequest(12, cert1, cert1, Constants.pkcs10_1, Constants.pkcs10_2));
		msghome.create("SimpleCardRenewalTest", smgs);
        msg = waitForUser("SimpleCardRenewalTest");
		assertNotNull(msg);
		submessagesresp = msg.getSubMessages(null,null,null);
		assertTrue("Number of submessages " + submessagesresp.getSubMessages().size(), submessagesresp.getSubMessages().size() == 1);
		resp = (ExtRAResponse) submessagesresp.getSubMessages().iterator().next();
		assertTrue("Wrong Request ID" + resp.getRequestId(), resp.getRequestId() == 12);
        assertTrue(resp.isSuccessful() == false);
        assertEquals(resp.getFailInfo(), "Verify failed for signature request");
        
        // Fourth fail message
        smgs = new SubMessages(null,null,null);
        smgs.addSubMessage(new CardRenewalRequest(12, cert1, cert2, Constants.pkcs10_1, Constants.pkcs10_2));
        msghome.create("SimpleCardRenewalTest", smgs);
        msg = waitForUser("SimpleCardRenewalTest");
        assertNotNull(msg);
        submessagesresp = msg.getSubMessages(null,null,null);
        assertTrue("Number of submessages " + submessagesresp.getSubMessages().size(), submessagesresp.getSubMessages().size() == 1);
        resp = (ExtRAResponse) submessagesresp.getSubMessages().iterator().next();
        assertTrue("Wrong Request ID" + resp.getRequestId(), resp.getRequestId() == 12);
        assertTrue(resp.isSuccessful() == false);
        assertEquals(resp.getFailInfo(), "User status must be new for SimplePKCS10Test1NoAdd");
        
        // TODO: make a successful message, but user status must be set to new then
	}
	
	
	private Message waitForUser(String user) throws InterruptedException{
		int waittime = 30; // Wait a maximum of 30 seconds
		boolean processed = false;
		Message msg = null;
		do{			
			msg = msghome.findByMessageId(user);
			assertNotNull(msg);
			
			if(msg.getStatus().equals(Message.STATUS_PROCESSED)){
				processed = true;
				break;
			}	
			Thread.sleep(1000);
		}while( waittime-- >= 0);
		if(!processed){
			msg = null;
		}
		return msg;
	}

    public byte[] generatePKCS10Req(String dn, String password) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, InvalidAlgorithmParameterException {
        // Generate keys
    	KeyPair keys = KeyTools.genKeys("512", CATokenConstants.KEYALGORITHM_RSA);            

        // Create challenge password attribute for PKCS10
        // Attributes { ATTRIBUTE:IOSet } ::= SET OF Attribute{{ IOSet }}
        //
        // Attribute { ATTRIBUTE:IOSet } ::= SEQUENCE {
        //    type    ATTRIBUTE.&id({IOSet}),
        //    values  SET SIZE(1..MAX) OF ATTRIBUTE.&Type({IOSet}{\@type})
        // }
        ASN1EncodableVector vec = new ASN1EncodableVector();
        vec.add(PKCSObjectIdentifiers.pkcs_9_at_challengePassword); 
        ASN1EncodableVector values = new ASN1EncodableVector();
        values.add(new DERUTF8String(password));
        vec.add(new DERSet(values));
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DERSequence(vec));
        DERSet set = new DERSet(v);
        // Create PKCS#10 certificate request
        PKCS10CertificationRequest p10request = new PKCS10CertificationRequest("SHA1WithRSA",
                CertTools.stringToBcX509Name(dn), keys.getPublic(), set, keys.getPrivate());
        
        return p10request.getEncoded();        
    }
}
