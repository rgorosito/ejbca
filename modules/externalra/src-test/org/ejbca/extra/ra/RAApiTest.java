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
package org.ejbca.extra.ra;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Random;

import javax.persistence.Persistence;

import org.apache.log4j.Logger;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.core.model.SecConst;
import org.ejbca.extra.db.CardRenewalRequest;
import org.ejbca.extra.db.CertificateRequestRequest;
import org.ejbca.extra.db.CertificateRequestResponse;
import org.ejbca.extra.db.Constants;
import org.ejbca.extra.db.EditUserRequest;
import org.ejbca.extra.db.ExtRAMessagesTest;
import org.ejbca.extra.db.ExtRAResponse;
import org.ejbca.extra.db.ISubMessage;
import org.ejbca.extra.db.KeyStoreRetrievalRequest;
import org.ejbca.extra.db.KeyStoreRetrievalResponse;
import org.ejbca.extra.db.Message;
import org.ejbca.extra.db.MessageHome;
import org.ejbca.extra.db.PKCS10Response;
import org.ejbca.extra.db.PKCS12Response;
import org.ejbca.extra.db.RevocationRequest;
import org.ejbca.extra.db.SubMessages;
import org.ejbca.util.NonEjbTestTools;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;


/**
 * JUnit test used to test the ExtRA API in a similar environment as used in production. Will connect to a RA message database and
 * sent messages that should be pulled and processed by the CA.
 * 
 * The test makes a full scale tests of sending PKCS10 and PKCS12 request to the CA and waits
 * for proper responses. May take some time and check the server log for errors. Revocation of
 * some of the generated certificates is also tested.
 * 
 * The following requirements should be set in order to run the tests.
 * - Properly configured database, see persistence-test.xml, default database 'messages' on localhost with user/pass ejbca/ejbca.
 * - External RA CA-service worker installed on EJBCA machine with datasource configured, see conf/externalra.properties
 * 
 * @version $Id$
 */

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class RAApiTest {

	private static final Logger log = Logger.getLogger(RAApiTest.class);
		
	@BeforeClass
	public static void beforeClass() throws Exception {
		CryptoProviderTools.installBCProvider();			
	}
	
	private static X509Certificate firstCertificate = null;
	private static X509Certificate secondCertificate = null;
	
	private static MessageHome msghome = new MessageHome(Persistence.createEntityManagerFactory("external-ra-test"), MessageHome.MESSAGETYPE_EXTRA, true);

    @Test	
	public void test01GenerateSimplePKCS10Request() throws Exception {

		SubMessages smgs = new SubMessages(null,null,null);
		smgs.addSubMessage(ExtRAMessagesTest.genExtRAPKCS10Request(100,"SimplePKCS10Test1", Constants.pkcs10_1));
		smgs.addSubMessage(ExtRAMessagesTest.genExtRAPKCS10Request(101,"SimplePKCS10Test1", Constants.pkcs10_2));
		
		msghome.create("SimplePKCS10Test1", smgs);
		
        Message msg = waitForUser("SimplePKCS10Test1");
		
		assertNotNull("No response.", msg);
		
		SubMessages submessagesresp = msg.getSubMessages(null,null);
		
		assertTrue(submessagesresp.getSubMessages().size() == 2);
		
		Iterator<ISubMessage> iter =  submessagesresp.getSubMessages().iterator();
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
        @SuppressWarnings("unchecked")
        Collection<SignerInformation> col = signers.getSigners();
        assertTrue(col.size() > 0);
        Iterator<SignerInformation> siter = col.iterator();
        SignerInformation signerInfo = (SignerInformation)siter.next();
        SignerId sinfo = signerInfo.getSID();
        // Check that the signer is the expected CA
        assertEquals(CertTools.stringToBCDNString(firstCertificate.getIssuerDN().getName()), CertTools.stringToBCDNString(sinfo.getIssuer().toString()));
        CertStore certstore = s.getCertificatesAndCRLs("Collection","BC");
        @SuppressWarnings({ "unchecked"})
        Collection<Certificate> certs = (Collection<Certificate>) certstore.getCertificates(null);
        assertEquals(certs.size(), 2);                	
        Iterator<Certificate> it = certs.iterator();
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
	}
	
    @Test
	public void test02GenerateSimplePKCS10RequestNoCreateUser() throws Exception {

		// First test with a user that does not exist or has status generated, when the user it not created the request will fail
		SubMessages smgs = new SubMessages(null,null,null);
		smgs.addSubMessage(ExtRAMessagesTest.genExtRAPKCS10Request(100,"SimplePKCS10Test1", Constants.pkcs10_1, false));
		msghome.create("SimplePKCS10Test1", smgs);
        Message msg = waitForUser("SimplePKCS10Test1");
		assertNotNull("No response", msg);
		SubMessages submessagesresp = msg.getSubMessages(null,null);
		assertTrue(submessagesresp.getSubMessages().size() == 1);		
		Iterator<ISubMessage> iter =  submessagesresp.getSubMessages().iterator();
		PKCS10Response resp = (PKCS10Response) iter.next();
		assertTrue(resp.getRequestId() == 100);
		assertTrue(resp.isSuccessful() == false);
		
		// if we create the user first, with correct status, the request should be ok, but only if we use the right password
		smgs = new SubMessages(null,null,null);
		smgs.addSubMessage(ExtRAMessagesTest.genExtRAPKCS10UserRequest(101,"SimplePKCS10Test1", "foo123"));
		msghome.create("SimplePKCS10Test1", smgs);		
        msg = waitForUser("SimplePKCS10Test1");
		assertNotNull(msg);
		submessagesresp = msg.getSubMessages(null,null);
		assertTrue("Number of submessages " + submessagesresp.getSubMessages().size(), submessagesresp.getSubMessages().size() == 1);
		ExtRAResponse editresp = (ExtRAResponse) submessagesresp.getSubMessages().iterator().next();
		assertTrue("Wrong Request ID" + editresp.getRequestId(), editresp.getRequestId() == 101);
		assertTrue("External RA CA Service was not successful.", editresp.isSuccessful() == true);

		// First test a request with wrong password, should not work
		smgs = new SubMessages(null,null,null);
		smgs.addSubMessage(ExtRAMessagesTest.genExtRAPKCS10Request(100,"SimplePKCS10Test1", Constants.pkcs10_3, false));
		msghome.create("SimplePKCS10Test1", smgs);
		msg = waitForUser("SimplePKCS10Test1");
		assertNotNull("No response", msg);
		submessagesresp = msg.getSubMessages(null,null);
		assertTrue(submessagesresp.getSubMessages().size() == 1);       
		iter =  submessagesresp.getSubMessages().iterator();
		resp = (PKCS10Response) iter.next();
		assertTrue(resp.getRequestId() == 100);
		assertTrue(resp.isSuccessful() == false);

		// Create a new request with right password, now it should be ok
		smgs = new SubMessages(null,null,null);
		smgs.addSubMessage(ExtRAMessagesTest.genExtRAPKCS10Request(102,"SimplePKCS10Test1", Constants.pkcs10_1, false));
		msghome.create("SimplePKCS10Test1", smgs);		
        msg = waitForUser("SimplePKCS10Test1");
		assertNotNull(msg);
		submessagesresp = msg.getSubMessages(null,null);
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
        @SuppressWarnings("unchecked")
        Collection<SignerInformation>col = signers.getSigners();
        assertTrue(col.size() > 0);
        Iterator<SignerInformation> siter = col.iterator();
        SignerInformation signerInfo = (SignerInformation)siter.next();
        SignerId sinfo = signerInfo.getSID();
        // Check that the signer is the expected CA
        assertEquals(CertTools.stringToBCDNString(firstCertificate.getIssuerDN().getName()), CertTools.stringToBCDNString(sinfo.getIssuer().toString()));
        CertStore certstore = s.getCertificatesAndCRLs("Collection","BC");
        @SuppressWarnings("unchecked")
        Collection<Certificate> certs = (Collection<Certificate>) certstore.getCertificates(null);
        assertEquals(certs.size(), 2);                	
        Iterator<Certificate> it = certs.iterator();
        boolean found = false;
        while (it.hasNext()) {
            X509Certificate retcert = (X509Certificate)it.next();
            if (retcert.getSubjectDN().equals(firstCertificate.getSubjectDN())) {
            	found = true;
            }
        }
        assertTrue(found);
	}

    @Test
	public void test03GenerateSimplePKCS12Request() throws Exception {		
		SubMessages smgs = new SubMessages(null,null,null);
		smgs.addSubMessage(ExtRAMessagesTest.genExtRAPKCS12Request(200,"SimplePKCS12Test1", false));
		
		msghome.create("SimplePKCS12Test1", smgs);
		
        Message msg = waitForUser("SimplePKCS12Test1");
		assertNotNull("No response.", msg);
		
		SubMessages submessagesresp = msg.getSubMessages(null,null);
		
		assertEquals(1, submessagesresp.getSubMessages().size());
		
		PKCS12Response resp = (PKCS12Response) submessagesresp.getSubMessages().iterator().next();
		assertEquals(200, resp.getRequestId());
		assertTrue(resp.isSuccessful());
		assertNotNull(resp.getKeyStore("foo123"));
		KeyStore ks = resp.getKeyStore("foo123");
		Enumeration<String> aliases = ks.aliases();
		String alias = null;
		while (aliases.hasMoreElements()) {
		    // Keystore aliases do not have a pre-defined order, so we have to look for the key entry.
		    // There are two entries, a key entry and a certificate entry for the CA certificate(s)
		    alias = aliases.nextElement();
	        if (ks.isKeyEntry(alias)) {
	            // We found the key entry and not the CA certificate entry
	            break;
	        }
		}
		assertEquals("Returned subject DN in generated certificate is not what we expected for alias: "+alias, "CN=PKCS12REQ", ((X509Certificate) ks.getCertificate(alias)).getSubjectDN().toString());
	}
	
	/** This test requires that keyrecovery is enabled in the EJBCA Admin-GUI */
    @Test
    public void test04GenerateSimpleKeyRecoveryRequest() throws Exception {
		// First generate keystore
		SubMessages smgs = new SubMessages(null,null,null);
		smgs.addSubMessage(ExtRAMessagesTest.genExtRAPKCS12Request(300,"SimplePKCS12Test1", true));
		
		msghome.create("SimplePKCS12Test1", smgs);
		
        Message msg = waitForUser("SimplePKCS12Test1");
		assertNotNull("No response.", msg);
		
		SubMessages submessagesresp = msg.getSubMessages(null,null);
		
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
		smgs.addSubMessage(ExtRAMessagesTest.genExtRAKeyRecoveryRequest(301,"SimplePKCS12Test1",true,orgCert));
		
		msghome.create("SimplePKCS12Test1", smgs);
		
        msg = waitForUser("SimplePKCS12Test1");
		
		assertNotNull(msg);
		
		submessagesresp = msg.getSubMessages(null,null);
		
		assertTrue(submessagesresp.getSubMessages().size() == 1);
		
		resp = (PKCS12Response) submessagesresp.getSubMessages().iterator().next();
		assertEquals(301, resp.getRequestId());
		assertTrue(resp.isSuccessful());
		
		X509Certificate keyRecCert = (X509Certificate) resp.getKeyStore("foo123").getCertificate("PKCS12REQ");
        assertTrue(keyRecCert.getSerialNumber().equals(orgCert.getSerialNumber()));
        
        // Generate Key Recovery Request with new cert
        
		smgs = new SubMessages(null,null,null);
		smgs.addSubMessage(ExtRAMessagesTest.genExtRAKeyRecoveryRequest(302,"SimplePKCS12Test1",false,orgCert));
		
		msghome.create("SimplePKCS12Test1", smgs);
		
        msg = waitForUser("SimplePKCS12Test1");
		
		assertNotNull(msg);
		
		submessagesresp = msg.getSubMessages(null,null);
		
		assertTrue(submessagesresp.getSubMessages().size() == 1);
		
		resp = (PKCS12Response) submessagesresp.getSubMessages().iterator().next();
		assertTrue(resp.getRequestId() == 302);
		assertTrue(resp.isSuccessful() == true);
		
		keyRecCert = (X509Certificate) resp.getKeyStore("foo123").getCertificate("KEYRECREQ");
        assertFalse(keyRecCert.getSerialNumber().equals(orgCert.getSerialNumber()));
	}
	
    @Test
    public void test05GenerateSimpleRevokationRequest() throws Exception {
		// revoke first certificate
		SubMessages smgs = new SubMessages(null,null,null);
		assertNotNull("Missing certificate from previous test.", firstCertificate);
		smgs.addSubMessage(new RevocationRequest(10, CertTools.getIssuerDN(firstCertificate), firstCertificate.getSerialNumber(), RevocationRequest.REVOKATION_REASON_UNSPECIFIED));
		
		msghome.create("SimpleRevocationTest", smgs);
		
        Message msg = waitForUser("SimpleRevocationTest");
		assertNotNull("No response.", msg);
		
		SubMessages submessagesresp = msg.getSubMessages(null,null);
		
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
		
		SubMessages submessagesresp2 = msg2.getSubMessages(null,null);
		
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
		
		SubMessages submessagesresp3 = msg3.getSubMessages(null,null);
		
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
		
		SubMessages submessagesresp4 = msg4.getSubMessages(null,null);
		
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
		
		SubMessages submessagesresp5 = msg5.getSubMessages(null,null);
		
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
		SubMessages submessagesresp6 = msg6.getSubMessages(null,null);
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
        SubMessages submessagesresp7 = msg7.getSubMessages(null,null);
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
        SubMessages submessagesresp8 = msg8.getSubMessages(null,null);
        assertTrue(submessagesresp8.getSubMessages().size() == 1);
        ExtRAResponse resp8 = (ExtRAResponse) submessagesresp8.getSubMessages().iterator().next();
        assertTrue(resp8.getRequestId() == 12);
        assertTrue(resp8.isSuccessful() == false);
        assertEquals(resp8.getFailInfo(), "User not found from issuer/serno: issuer='CN=ffo558444,O=338qqwaa,C=qq', serno=123");
	}
	
    @Test
	public void test06GenerateSimpleEditUserRequest() throws Exception {
		
		// edit a user
		SubMessages smgs = new SubMessages(null,null,null);
		smgs.addSubMessage(ExtRAMessagesTest.genExtRAEditUserRequest(11,"SimpleEditUserTest"));
		
		msghome.create("SimpleEditUserTest", smgs);
		
        Message msg = waitForUser("SimpleEditUserTest");
		assertNotNull("No response.", msg);
		
		SubMessages submessagesresp = msg.getSubMessages(null,null);
		
		assertTrue("Number of submessages " + submessagesresp.getSubMessages().size(), submessagesresp.getSubMessages().size() == 1);
		
		ExtRAResponse resp = (ExtRAResponse) submessagesresp.getSubMessages().iterator().next();
		assertTrue("Wrong Request ID" + resp.getRequestId(), resp.getRequestId() == 11);
		assertTrue(resp.isSuccessful() == true);
	}	
	
    @Test
	public void test07GenerateComplexRequest() throws Exception {
		
		SubMessages smgs = new SubMessages(null,null,null);
		smgs.addSubMessage(ExtRAMessagesTest.genExtRAPKCS10Request(1,"SimplePKCS10Test1", Constants.pkcs10_1));
		smgs.addSubMessage(ExtRAMessagesTest.genExtRAPKCS12Request(2,"SimplePKCS12Test1", false));
		smgs.addSubMessage(ExtRAMessagesTest.genExtRAPKCS12Request(3,"SimplePKCS12Test1", false));
		
		msghome.create("COMPLEXREQ_1", smgs);
		
        Message msg = waitForUser("COMPLEXREQ_1");
		assertNotNull("No response.", msg);
		
		SubMessages submessagesresp = msg.getSubMessages(null,null);
		
		assertTrue(submessagesresp.getSubMessages().size() == 3);
		
		
		Iterator<ISubMessage> iter = submessagesresp.getSubMessages().iterator();
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
	
    @Test
	public void test08GenerateLotsOfRequest() throws Exception {
		
		int numberOfRequests = 10;
		
		for(int i=0; i< numberOfRequests; i++){
		  SubMessages smgs = new SubMessages(null,null,null);
		  smgs.addSubMessage(ExtRAMessagesTest.genExtRAPKCS10Request(1,"SimplePKCS10Test1", Constants.pkcs10_1));		
		  msghome.create("LotsOfReq" + i, smgs);
		}

		Message[] resps = new Message[numberOfRequests];
		for(int i=0; i < numberOfRequests; i++){
			resps[i] = waitForUser("LotsOfReq"+i);
			assertNotNull("No response.", resps[i]);
			SubMessages submessagesresp = resps[i].getSubMessages(null,null);
			PKCS10Response resp = (PKCS10Response) submessagesresp.getSubMessages().iterator().next();
			assertTrue(resp.isSuccessful() == true);
		}								
	} 
	
    @Test
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
		SubMessages submessagesresp = msg.getSubMessages(null,null);
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
		submessagesresp = msg.getSubMessages(null,null);
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
		submessagesresp = msg.getSubMessages(null,null);
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
        submessagesresp = msg.getSubMessages(null,null);
        assertTrue("Number of submessages " + submessagesresp.getSubMessages().size(), submessagesresp.getSubMessages().size() == 1);
        resp = (ExtRAResponse) submessagesresp.getSubMessages().iterator().next();
        assertTrue("Wrong Request ID" + resp.getRequestId(), resp.getRequestId() == 12);
        assertTrue(resp.isSuccessful() == false);
        log.debug("resp.getFailInfo: " + resp.getFailInfo());
        assertEquals("Wrong error message.", resp.getFailInfo(), "User status must be new for SimplePKCS10Test1");
        
        // TODO: make a successful message, but user status must be set to new then
	}
	
	/**
	 * Add a user and retrieve a keystore for this user.
	 */
    @Test
	public void test10KeyStoreRetrieval() throws Exception {
		Random random = new Random();
		long requestId = random.nextLong();
		String username = "ExtRA-ksret-" + random.nextInt();
		String password = "foo123";
		// Add a new user
		EditUserRequest editUserRequest = new EditUserRequest(requestId, username, "CN=" + username, null, null, null, "EMPTY", "ENDUSER", 
                   "ManagementCA", password, 10, 1, EditUserRequest.SOFTTOKENNAME_P12, null);
		SubMessages smgs = new SubMessages(null,null,null);
		smgs.addSubMessage(editUserRequest);
		msghome.create(username, smgs);
        Message msg = waitForUser(username);
		assertNotNull("No response.", msg);
		SubMessages submessagesresp = msg.getSubMessages(null,null);
		assertTrue("Number of submessages " + submessagesresp.getSubMessages().size(), submessagesresp.getSubMessages().size() == 1);
		ExtRAResponse resp = (ExtRAResponse) submessagesresp.getSubMessages().iterator().next();
		assertTrue("Wrong Request ID: " + resp.getRequestId(), resp.getRequestId() == requestId);
		assertTrue("Edit user failed", resp.isSuccessful() == true);
		// Try to retrieve keystore
		requestId = random.nextLong();
		KeyStoreRetrievalRequest keyStoreRetrievalRequest = new KeyStoreRetrievalRequest(requestId, username, password);
		smgs = new SubMessages(null,null,null);
		smgs.addSubMessage(keyStoreRetrievalRequest);
		msghome.create(username+"ks", smgs);
        msg = waitForUser(username+"ks");
		assertNotNull("No response.", msg);
		submessagesresp = msg.getSubMessages(null,null);
		assertTrue("Number of submessages " + submessagesresp.getSubMessages().size(), submessagesresp.getSubMessages().size() == 1);
		resp = (ExtRAResponse) submessagesresp.getSubMessages().iterator().next();
		assertTrue("Wrong Request ID: " + resp.getRequestId(), resp.getRequestId() == requestId);
		assertTrue("KeyStoreRetrieval failed", resp.isSuccessful() == true);
		assertTrue("Wrong response type.", resp instanceof KeyStoreRetrievalResponse);
		KeyStoreRetrievalResponse ksResp = (KeyStoreRetrievalResponse) resp;
		assertTrue("Wrong keystore type.", ksResp.getKeyStoreType() == SecConst.TOKEN_SOFT_P12);
		KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
		try {
			ks.load(new ByteArrayInputStream(ksResp.getKeyStoreData()), password.toCharArray());
		} catch (Exception e) {
			assertTrue("Could not recreate keystore from response.", false);
		}
	}	
	
	/**
	 * Add a user and fetch a certificate for this user.
	 */
    @Test
	public void test11CertificateFromCSR() throws Exception {
		Random random = new Random();
		long requestId = random.nextLong();
		String username = "ExtRA-ksret-" + random.nextInt();
		String password = "foo123";
		// Add a new user
		EditUserRequest editUserRequest = new EditUserRequest(requestId, username, "CN=" + username, null, null, null, "EMPTY", "ENDUSER", 
                   "ManagementCA", password, 10, 1, EditUserRequest.SOFTTOKENNAME_USERGENERATED, null);
		SubMessages smgs = new SubMessages(null,null,null);
		smgs.addSubMessage(editUserRequest);
		msghome.create(username, smgs);
        Message msg = waitForUser(username);
		assertNotNull("No response.", msg);
		SubMessages submessagesresp = msg.getSubMessages(null,null);
		assertTrue("Number of submessages " + submessagesresp.getSubMessages().size(), submessagesresp.getSubMessages().size() == 1);
		ExtRAResponse resp = (ExtRAResponse) submessagesresp.getSubMessages().iterator().next();
		assertTrue("Wrong Request ID" + resp.getRequestId(), resp.getRequestId() == requestId);
		assertTrue("Edit user failed", resp.isSuccessful() == true);
		// Try to retrieve keystore
		requestId = random.nextLong();
		byte[] requestData = NonEjbTestTools.generatePKCS10Req("CN=dummyname", password);
		CertificateRequestRequest certificateRequestRequest = new CertificateRequestRequest(requestId, username, password, CertificateRequestRequest.REQUEST_TYPE_PKCS10, requestData, CertificateRequestRequest.RESPONSE_TYPE_ENCODED);
		smgs = new SubMessages(null,null,null);
		smgs.addSubMessage(certificateRequestRequest);
		msghome.create(username+"csr", smgs);
        msg = waitForUser(username+"csr");
		assertNotNull("No response.", msg);
		submessagesresp = msg.getSubMessages(null,null);
		assertTrue("Number of submessages " + submessagesresp.getSubMessages().size(), submessagesresp.getSubMessages().size() == 1);
		resp = (ExtRAResponse) submessagesresp.getSubMessages().iterator().next();
		assertTrue("Wrong Request ID" + resp.getRequestId(), resp.getRequestId() == requestId);
		assertTrue("KeyStoreRetrieval failed", resp.isSuccessful() == true);
		assertTrue("Wrong response type.", resp instanceof CertificateRequestResponse);
		CertificateRequestResponse certResp = (CertificateRequestResponse) resp;
		assertTrue("Wrong keystore type.", certResp.getResponseType() == CertificateRequestRequest.RESPONSE_TYPE_ENCODED);
		assertTrue("Wrong certificate in response", CertTools.getSubjectDN(CertTools.getCertfromByteArray(certResp.getResponseData())).equals("CN="+username));
	}	
	
	/**
	 * Request certificate for a new user using the OneshotCertReqRequest.
	 */
    @Test
	public void test12OneshotCertReq() throws Exception {
		final Random random = new Random();
		final long requestId = random.nextLong();
		final String username = "ExtRA-oneshot-" + random.nextInt();
		final String password = "foo12345";
		
		// Create request
		final KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
		final byte[] requestData = new String("-----BEGIN CERTIFICATE REQUEST-----\n"
				+ new String(Base64.encode(CertTools.genPKCS10CertificationRequest("SHA1WithRSA",
		                CertTools.stringToBcX500Name("CN=oneshot-dummyname"), keys.getPublic(), null, keys.getPrivate(), null).getEncoded()))
				+ "\n-----END CERTIFICATE REQUEST-----").getBytes();
		
		final CertificateRequestRequest request = new CertificateRequestRequest(
				requestId,
				username, 
				"CN=" + username, 
				null, 
				null, 
				null, 
				"EMPTY", 
				"ENDUSER", 
				"ManagementCA", 
				null, 
				password, 
				CertificateRequestRequest.REQUEST_TYPE_PKCS10, requestData, CertificateRequestRequest.RESPONSE_TYPE_CERTIFICATE);
		request.setCreateOrEditUser(true);
		
		final SubMessages smgs = new SubMessages(null,null,null);
		smgs.addSubMessage(request);
		msghome.create(username + "csr", smgs);
        
		final Message msg = waitForUser(username + "csr");
        assertNotNull("No response.", msg);
		final SubMessages submessagesresp = msg.getSubMessages(null,null);
		assertEquals("Number of submessages " + submessagesresp.getSubMessages().size(), 1, submessagesresp.getSubMessages().size());
		final ExtRAResponse resp = (ExtRAResponse) submessagesresp.getSubMessages().iterator().next();
		assertEquals("Wrong Request ID" + resp.getRequestId(), requestId, resp.getRequestId());
		assertTrue("KeyStoreRetrieval failed: " + resp.getFailInfo(), resp.isSuccessful());
		assertTrue("Wrong response type.", resp instanceof CertificateRequestResponse);
		final CertificateRequestResponse certResp = (CertificateRequestResponse) resp;
		assertEquals("Wrong keystore type.", CertificateRequestRequest.RESPONSE_TYPE_CERTIFICATE, certResp.getResponseType());
		assertEquals("Wrong certificate in response", "CN=" + username, CertTools.getSubjectDN(CertTools.getCertfromByteArray(certResp.getResponseData())));
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
}
