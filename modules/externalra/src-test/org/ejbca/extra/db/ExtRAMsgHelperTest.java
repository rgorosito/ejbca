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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;

import org.cesecore.util.CryptoProviderTools;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Performs test related to encryption/signature of messages.
 *
 * @version $Id$
 */
public class ExtRAMsgHelperTest {

    @BeforeClass
	public static void beforeClass() throws Exception {
		CryptoProviderTools.installBCProvider();
	}

	/*
	 * Test method for 'org.ejbca.extra.db.ExtRAMsgHelper.encryptData(X509Certificate, byte[])'
	 */
    @Test
	public void testEncryptDecryptData() throws Exception {
       String testdata = "TESTDATA";
       
       byte[] encdata = ExtRAMsgHelper.encryptData(Constants.getUserCert(),testdata.getBytes());
       
       String decdata = new String(ExtRAMsgHelper.decryptData(Constants.getUserKey(),encdata));
       assertTrue(testdata.equals(decdata));
       
       encdata = ExtRAMsgHelper.encryptData(Constants.getRootCert(),testdata.getBytes());
             
       byte[] decdata2 = ExtRAMsgHelper.decryptData(Constants.getUserKey(),encdata);
       assertTrue(decdata2 == null);
       
	}

	/*
	 * Test method for 'org.ejbca.extra.db.ExtRAMsgHelper.signData(PrivateKey, X509Certificate, byte[])'
	 */
    @Test
	public void testSignVerifyData() throws Exception {
		
		String testdata = "DATATOSIGN";
		
		byte[] signeddata = ExtRAMsgHelper.signData(Constants.getUserKey(),Constants.getUserCert(), testdata.getBytes());
		assertNotNull(signeddata);
		
		List<Certificate> caCertChain = new ArrayList<Certificate>();
		caCertChain.add(Constants.getRootCert());
		caCertChain.add(Constants.getIntermediateCert());
		
		assertTrue((ExtRAMsgHelper.verifySignature(caCertChain, signeddata)).isValid());
		
		// Test inverted certchain
		List<Certificate> caCertChain2 = new ArrayList<Certificate>();
		caCertChain2.add(Constants.getIntermediateCert());
		caCertChain2.add(Constants.getRootCert());
		assertTrue((ExtRAMsgHelper.verifySignature(caCertChain2, signeddata)).isValid());  
		
		// Test to sign with incomplete Certchain, no intermediate
		List<Certificate> caCertChain3 = new ArrayList<Certificate>();
		caCertChain3.add(Constants.getRootCert());
		assertFalse((ExtRAMsgHelper.verifySignature(caCertChain3, signeddata)).isValid());
		
        //	Test to sign with incomplete Certchain, no admin
		List<Certificate> caCertChain4 = new ArrayList<Certificate>();
		caCertChain4.add(Constants.getIntermediateCert());
		assertFalse((ExtRAMsgHelper.verifySignature(caCertChain4, signeddata)).isValid());
		
		// Test expired certificates
        Calendar invalidDate = Calendar.getInstance();
        invalidDate.set(2002,2,21,2,21,10);
        assertFalse((ExtRAMsgHelper.verifySignature(caCertChain, signeddata, invalidDate.getTime())).isValid());
                
        invalidDate.set(2050,2,21,2,21,10);
        assertFalse((ExtRAMsgHelper.verifySignature(caCertChain, signeddata, invalidDate.getTime())).isValid());
        
        // Test invalid signature cert
		byte[] signeddata2 = ExtRAMsgHelper.signData(Constants.getUserKey(),Constants.getIntermediateCert(), testdata.getBytes());
		assertNotNull(signeddata);
		
		List<Certificate> caCertChain5 = new ArrayList<Certificate>();
		caCertChain5.add(Constants.getRootCert());
				
		assertFalse((ExtRAMsgHelper.verifySignature(caCertChain5, signeddata2)).isValid());
        
		// TODO test crl checks
	}
}
