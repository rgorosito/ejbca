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
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertStoreException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.certificates.certificate.request.ResponseStatus;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.core.protocol.scep.ScepRequestMessage;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests SCEP enrollment with an RA (SCEP polling RA mode).
 * This test assumes a CA hierarchy. One root CA ManagementCA and one sub CA ScepCA.
 * 
 * @version $Id$
 */
public class ProtocolScepHttpTest {
    private static Logger log = Logger.getLogger(ProtocolScepHttpTest.class);

    private static final String httpReqPath = "http://127.0.0.1:8080";
    private static final String resourceScep = "/scepraserver/scep/pkiclient.exe";
    private static final String resourceScepNoCA = "/scepraserver/scep/noca/pkiclient.exe";
    private static final String radn = "CN=Scep RA,O=PrimeKey,C=SE";
    private static final String cadn = "CN=Scep CA,O=EJBCA Sample,C=SE";
    private static final String rootcadn = "CN=ManagementCA,O=EJBCA Sample,C=SE";

    private static X509Certificate rootcacert = null;
    private static X509Certificate cacert = null;
    private static X509Certificate racert = null;
    private static KeyPair keys = null;
    
    private String transId = null;
    private String senderNonce = null;

    @BeforeClass
    public static void beforeClass() throws Exception {
        // Install BouncyCastle provider
        CryptoProviderTools.installBCProvider();
		if (keys == null) {
			keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
		}
    }

    // GetCACert and GetCACertChain behaves the same if it is an RA that responds
    @Test
    public void test02ScepGetCACert() throws Exception {
        log.debug(">test02ScepGetCACert()");
    	scepGetCACertChain("GetCACert", "application/x-x509-ca-ra-cert");    	
        log.debug(">test02ScepGetCACert()");
    }

    @Test
    public void test03ScepGetCACertChain() throws Exception {
        log.debug(">test03ScepGetCACertChain()");
    	scepGetCACertChain("GetCACertChain", "application/x-x509-ca-ra-cert-chain");    	
        log.debug(">test03ScepGetCACertChain()");
    }
    private void scepGetCACertChain(String method, String mimetype) throws Exception {
        String reqUrl = httpReqPath + '/' + resourceScepNoCA+"?operation="+method+"&message=test";
        URL url = new URL(reqUrl);
        HttpURLConnection con = (HttpURLConnection)url.openConnection();
        con.setRequestMethod("GET");
        con.getDoOutput();
        con.connect();
        assertEquals("Response code", 200, con.getResponseCode());
        assertEquals("Content-Type", mimetype, con.getContentType());
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // This works for small requests, and SCEP requests are small enough
        InputStream in = con.getInputStream();
        int b = in.read();
        while (b != -1) {
            baos.write(b);
            b = in.read();
        }
        baos.flush();
        in.close();
        byte[] respBytes = baos.toByteArray();
        assertNotNull("Response can not be null.", respBytes);
        assertTrue(respBytes.length > 0);
        
        CMSSignedData s = new CMSSignedData(respBytes);
        assertNotNull(s);
        SignerInformationStore signers = s.getSignerInfos();
        @SuppressWarnings("unchecked")
        Collection<SignerInformation> col = signers.getSigners();
        assertTrue(col.size() == 0);
        Store certstore = s.getCertificates();
        @SuppressWarnings("unchecked")
        List<X509CertificateHolder> certs = new ArrayList<X509CertificateHolder>(certstore.getMatches(null));
        // Length two if the Scep RA server is signed directly by a Root CA
        // Length three if the Scep RA server is signed by a CA which is signed by a Root CA
        assertEquals(3, certs.size());	   
        JcaX509CertificateConverter jcaX509CertificateConverter = new JcaX509CertificateConverter();
        racert = jcaX509CertificateConverter.getCertificate(certs.get(0));
        cacert = jcaX509CertificateConverter.getCertificate(certs.get(1));
        rootcacert = jcaX509CertificateConverter.getCertificate(certs.get(2));
        log.info("Got CA cert with DN: "+ cacert.getSubjectDN().getName());
        assertEquals(cadn, cacert.getSubjectDN().getName());
        log.info("Got Root CA cert with DN: "+ rootcacert.getSubjectDN().getName());
        assertEquals(rootcadn, rootcacert.getSubjectDN().getName());
        log.info("Got RA cert with DN: "+ racert.getSubjectDN().getName());
        assertEquals(radn, racert.getSubjectDN().getName());
    }
    
    @Test
    public void test04ScepGetCACaps() throws Exception {
        log.debug(">test04ScepGetCACaps()");
        String reqUrl = httpReqPath + '/' + resourceScep+"?operation=GetCACaps&message=test";
        URL url = new URL(reqUrl);
        HttpURLConnection con = (HttpURLConnection)url.openConnection();
        con.setRequestMethod("GET");
        con.getDoOutput();
        con.connect();
        assertEquals("Response code", 200, con.getResponseCode());
        assertEquals("Content-Type", "text/plain", con.getContentType());
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // This works for small requests, and SCEP requests are small enough
        InputStream in = con.getInputStream();
        int b = in.read();
        while (b != -1) {
            baos.write(b);
            b = in.read();
        }
        baos.flush();
        in.close();
        byte[] respBytes = baos.toByteArray();
        assertNotNull("Response can not be null.", respBytes);
        assertTrue(respBytes.length > 0);
        assertEquals(new String(respBytes), "POSTPKIOperation\nSHA-1");
        log.debug(">test04ScepGetCACaps()");
    }
    

    // This test will send a request and expect back a pending response.
    // It will then start polling the RA waiting for a real reply.
    // When polling it will accept a pending or a success reply
    @Test
    public void test05ScepRequestOKSHA1() throws Exception {
        log.debug(">test05ScepRequestOKSHA1()");
        // send SCEP req to RA server and get pending request, until the request is processed on the CA
        // Then we will get a certificate response back    
        ScepRequestGenerator gen = new ScepRequestGenerator();
        byte[] msgBytes = genScepRequest(gen);
        // Send message with GET
        byte[] retMsg = sendScep(false, msgBytes, false);
        assertNotNull(retMsg);
        checkScepResponse(retMsg, senderNonce, transId, false, CMSSignedGenerator.DIGEST_SHA1, false, ResponseStatus.PENDING);
        // Send GetCertInitial and wait for a certificate response, you will probably get PENDING reply several times
        int keeprunning = 0;
        boolean processed = false;
        while ( (keeprunning < 5) && !processed) {
        	log.info("Waiting 5 secs...");
        	Thread.sleep(5000); // wait 5 seconds between polls
            msgBytes = genScepGetCertInitial(gen);
            // Send message with GET
            retMsg = sendScep(false, msgBytes, false);
            assertNotNull(retMsg);
            if (isScepResponseMessageOfType(retMsg, ResponseStatus.PENDING)) {
            	log.info("Received a PENDING message");
                checkScepResponse(retMsg, senderNonce, transId, false, CMSSignedGenerator.DIGEST_SHA1, false, ResponseStatus.PENDING);            	
            } else {            	
            	log.info("Received a SUCCESS message");
                checkScepResponse(retMsg, senderNonce, transId, false, CMSSignedGenerator.DIGEST_SHA1, false, ResponseStatus.SUCCESS);
                processed = true;
            }
            keeprunning++;
        }
        assertTrue(processed);
        log.debug("<test05ScepRequestOKSHA1()");
    }
    
    
    // This test will send a request and expect back a pending response.
    // It will then start polling the RA waiting for a real reply.
    // When polling it will accept a pending or a success reply
    @Test
    public void test06ScepRequestOKSHA1PostNoCA() throws Exception {
        log.debug(">test06ScepRequestOKSHA1PostNoCA()");
        // send SCEP req to RA server and get pending request, until the request is processed on the CA
        // Then we will get a certificate response back    
        ScepRequestGenerator gen = new ScepRequestGenerator();
        byte[] msgBytes = genScepRequest(gen);
        // Send message with POST
        byte[] retMsg = sendScep(true, msgBytes, true);
        assertNotNull(retMsg);
        checkScepResponse(retMsg, senderNonce, transId, false, CMSSignedGenerator.DIGEST_SHA1, true, ResponseStatus.PENDING);
        // Send GetCertInitial and wait for a certificate response, you will probably get PENDING reply several times
        int keeprunning = 0;
        boolean processed = false;
        while ( (keeprunning < 5) && !processed) {
        	Thread.sleep(5000); // wait 5 seconds between polls
            msgBytes = genScepGetCertInitial(gen);
            // Send message with GET
            retMsg = sendScep(true, msgBytes, true);
            assertNotNull(retMsg);
            if (isScepResponseMessageOfType(retMsg, ResponseStatus.PENDING)) {
                checkScepResponse(retMsg, senderNonce, transId, false, CMSSignedGenerator.DIGEST_SHA1, true, ResponseStatus.PENDING);            	
            } else {            	
                checkScepResponse(retMsg, senderNonce, transId, false, CMSSignedGenerator.DIGEST_SHA1, true, ResponseStatus.SUCCESS);
                processed = true;
            }
            keeprunning++;
        }
        assertTrue(processed);
        log.debug("<test06ScepRequestOKSHA1PostNoCA()");
    }

    private byte[] genScepRequest(ScepRequestGenerator gen) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException,
            SignatureException, InvalidAlgorithmParameterException, CertStoreException, IOException, CMSException, IllegalStateException,
            OperatorCreationException, CertificateException {
        gen.setKeys(keys);
        byte[] msgBytes = null;
        String dn = "C=SE, O=PrimeKey, CN=sceptest";
        msgBytes = gen.generateCertReq(dn, "foo123", racert);
        assertNotNull(msgBytes);
        transId = gen.getTransactionId();
        assertNotNull(transId);
        byte[] idBytes = Base64.decode(transId.getBytes());
        assertEquals(16, idBytes.length);
        senderNonce = gen.getSenderNonce();
        byte[] nonceBytes = Base64.decode(senderNonce.getBytes());
        assertEquals(16, nonceBytes.length);
        return msgBytes;
    }

    private byte[] genScepGetCertInitial(ScepRequestGenerator gen) throws NoSuchAlgorithmException, NoSuchProviderException, IOException,
            CMSException, CertificateEncodingException, OperatorCreationException {
        gen.setKeys(keys);
        byte[] msgBytes = null;
        String dn = "C=SE, O=PrimeKey, CN=sceptest"; // must be same as when the request was generated
        msgBytes = gen.generateGetCertInitial(dn, racert);
        assertNotNull(msgBytes);
        transId = gen.getTransactionId();
        assertNotNull(transId);
        byte[] idBytes = Base64.decode(transId.getBytes());
        assertEquals(16, idBytes.length);
        senderNonce = gen.getSenderNonce();
        byte[] nonceBytes = Base64.decode(senderNonce.getBytes());
        assertEquals(16, nonceBytes.length);
        return msgBytes;
    }
    
    private boolean isScepResponseMessageOfType(byte[] retMsg, ResponseStatus extectedResponseStatus) throws CMSException, NoSuchAlgorithmException,
            NoSuchProviderException, OperatorCreationException {

        // Parse response message
        //
        CMSSignedData s = new CMSSignedData(retMsg);
        // The signer, i.e. the CA, check it's the right CA
        SignerInformationStore signers = s.getSignerInfos();
        @SuppressWarnings("unchecked")
        Collection<SignerInformation> col = signers.getSigners();
        assertTrue(col.size() > 0);
        Iterator<SignerInformation> iter = col.iterator();
        SignerInformation signerInfo = (SignerInformation)iter.next();
        SignerId sinfo = signerInfo.getSID();
        // Check that the signer is the expected CA
        assertEquals(CertTools.stringToBCDNString(racert.getIssuerDN().getName()), CertTools.stringToBCDNString(sinfo.getIssuer().toString()));
        // Verify the signature
        JcaDigestCalculatorProviderBuilder calculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder();
        JcaSignerInfoVerifierBuilder jcaSignerInfoVerifierBuilder = new JcaSignerInfoVerifierBuilder(calculatorProviderBuilder.build());
        boolean ret = signerInfo.verify(jcaSignerInfoVerifierBuilder.build(racert.getPublicKey()));
        assertTrue(ret);
        // Get authenticated attributes
        AttributeTable tab = signerInfo.getSignedAttributes();        
        // --Fail info
        Attribute attr = tab.get(new ASN1ObjectIdentifier(ScepRequestMessage.id_failInfo));
        // --Message type
        attr = tab.get(new ASN1ObjectIdentifier(ScepRequestMessage.id_messageType));
        assertNotNull(attr);
        ASN1Set values = attr.getAttrValues();
        assertEquals(values.size(), 1);
        ASN1String str = DERPrintableString.getInstance((values.getObjectAt(0)));
        String messageType = str.getString();
        assertEquals("3", messageType);
        // --Success status
        attr = tab.get(new ASN1ObjectIdentifier(ScepRequestMessage.id_pkiStatus));
        assertNotNull(attr);
        values = attr.getAttrValues();
        assertEquals(values.size(), 1);
        str = DERPrintableString.getInstance((values.getObjectAt(0)));
        String responsestatus =  str.getString();
        if (extectedResponseStatus.getStringValue().equals(responsestatus)) {
        	return true;
        }
        return false;
    }

    private void checkScepResponse(byte[] retMsg, String senderNonce, String transId, boolean crlRep, String digestOid, boolean noca,
            ResponseStatus expectedResponseStatus) throws CMSException, NoSuchProviderException, NoSuchAlgorithmException, CertStoreException,
            InvalidKeyException, CertificateException, SignatureException, CRLException, IOException, OperatorCreationException {
        // Parse response message
        //
        CMSSignedData s = new CMSSignedData(retMsg);
        // The signer, i.e. the CA, check it's the right CA
        SignerInformationStore signers = s.getSignerInfos();
        @SuppressWarnings("unchecked")
        Collection<SignerInformation> col = signers.getSigners();
        assertTrue(col.size() > 0);
        Iterator<SignerInformation> iter = col.iterator();
        SignerInformation signerInfo = iter.next();
        // Check that the message is signed with the correct digest alg
        assertEquals(signerInfo.getDigestAlgOID(), digestOid);
        SignerId sinfo = signerInfo.getSID();
        // Check that the signer is the expected CA
        assertEquals(CertTools.stringToBCDNString(racert.getIssuerDN().getName()), CertTools.stringToBCDNString(sinfo.getIssuer().toString()));
        // Verify the signature
        JcaDigestCalculatorProviderBuilder calculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder();
        JcaSignerInfoVerifierBuilder jcaSignerInfoVerifierBuilder = new JcaSignerInfoVerifierBuilder(calculatorProviderBuilder.build());
        boolean ret = signerInfo.verify(jcaSignerInfoVerifierBuilder.build(racert.getPublicKey()));
        assertTrue(ret);
        // Get authenticated attributes
        AttributeTable tab = signerInfo.getSignedAttributes();        
        // --Fail info
        Attribute attr = tab.get(new ASN1ObjectIdentifier(ScepRequestMessage.id_failInfo));
        // No failInfo on this success message
        if(expectedResponseStatus == ResponseStatus.SUCCESS){
          assertNull(attr);
        }  
          
        // --Message type
        attr = tab.get(new ASN1ObjectIdentifier(ScepRequestMessage.id_messageType));
        assertNotNull(attr);
        ASN1Set values = attr.getAttrValues();
        assertEquals(values.size(), 1);
        ASN1String str = DERPrintableString.getInstance((values.getObjectAt(0)));
        String messageType = str.getString();
        assertEquals("3", messageType);
        // --Success status
        attr = tab.get(new ASN1ObjectIdentifier(ScepRequestMessage.id_pkiStatus));
        assertNotNull(attr);
        values = attr.getAttrValues();
        assertEquals(values.size(), 1);
        str = DERPrintableString.getInstance((values.getObjectAt(0)));
        String responsestatus =  str.getString();
        assertEquals(expectedResponseStatus.getValue(), responsestatus);
        // --SenderNonce
        attr = tab.get(new ASN1ObjectIdentifier(ScepRequestMessage.id_senderNonce));
        assertNotNull(attr);
        values = attr.getAttrValues();
        assertEquals(values.size(), 1);
        ASN1OctetString octstr = ASN1OctetString.getInstance(values.getObjectAt(0));
        // SenderNonce is something the server came up with, but it should be 16 chars
        assertTrue(octstr.getOctets().length == 16);
        // --Recipient Nonce
        attr = tab.get(new ASN1ObjectIdentifier(ScepRequestMessage.id_recipientNonce));
        assertNotNull(attr);
        values = attr.getAttrValues();
        assertEquals(values.size(), 1);
        octstr = ASN1OctetString.getInstance(values.getObjectAt(0));
        // recipient nonce should be the same as we sent away as sender nonce
        assertEquals(senderNonce, new String(Base64.encode(octstr.getOctets())));
        // --Transaction ID
        attr = tab.get(new ASN1ObjectIdentifier(ScepRequestMessage.id_transId));
        assertNotNull(attr);
        values = attr.getAttrValues();
        assertEquals(values.size(), 1);
        str = DERPrintableString.getInstance((values.getObjectAt(0)));
        // transid should be the same as the one we sent
        assertEquals(transId, str.getString());
        
        //
        // Check different message types
        //        
        if (!responsestatus.equals(ResponseStatus.PENDING.getValue()) && messageType.equals("3")) {
            // First we extract the encrypted data from the CMS enveloped data contained
            // within the CMS signed data
            CMSProcessable sp = s.getSignedContent();
            byte[] content = (byte[])sp.getContent();
            CMSEnvelopedData ed = new CMSEnvelopedData(content);
            RecipientInformationStore recipients = ed.getRecipientInfos();
            @SuppressWarnings("unchecked")
            Collection<RecipientInformation> c = recipients.getRecipients();
            assertEquals(c.size(), 1);
            Iterator<RecipientInformation> recipientIterator = c.iterator();
            byte[] decBytes = null;
            RecipientInformation recipient = (RecipientInformation) recipientIterator.next();
            JceKeyTransEnvelopedRecipient rec = new JceKeyTransEnvelopedRecipient(keys.getPrivate());
            rec.setProvider(BouncyCastleProvider.PROVIDER_NAME);
            decBytes = recipient.getContent(rec);
            // This is yet another CMS signed data
            CMSSignedData sd = new CMSSignedData(decBytes);
            // Get certificates from the signed data
            Store certstore = sd.getCertificates();
            if (crlRep) {
                // We got a reply with a requested CRL
                @SuppressWarnings("unchecked")
                Collection<X509CRLHolder> crls = sd.getCRLs().getMatches(null);
                assertEquals(crls.size(), 1);
                Iterator<X509CRLHolder> it = crls.iterator();
                X509CRL retCrl = null;
                // CRL is first (and only)
                retCrl = new JcaX509CRLConverter().getCRL(it.next());
                log.info("Got CRL with DN: "+ retCrl.getIssuerDN().getName());
                // check the returned CRL
                assertEquals(cacert.getSubjectDN().getName(), retCrl.getIssuerDN().getName());
                retCrl.verify(cacert.getPublicKey());
            } else {
                // We got a reply with a requested certificate 
                @SuppressWarnings("unchecked")
                Collection<X509CertificateHolder> certs = certstore.getMatches(null);
                log.info("Got certificate reply with certchain of length: "+certs.size());
                // EJBCA returns the issued cert and the CA cert (cisco vpn client requires that the ca cert is included)
                if (noca) {
                    assertEquals(certs.size(), 1);	                	
                } else {
                    assertEquals(certs.size(), 2);                	
                }

                // Issued certificate must be first
                boolean verified = false;
                boolean gotcacert = false;
                String mysubjectdn = CertTools.stringToBCDNString("C=SE,O=PrimeKey,CN=sceptest");
                X509Certificate usercert = null;
                JcaX509CertificateConverter jcaX509CertificateConverter = new JcaX509CertificateConverter();
                for (X509CertificateHolder cert : certs) {
                    X509Certificate retcert = jcaX509CertificateConverter.getCertificate(cert);
                    // check the returned certificate
                    String subjectdn = CertTools.stringToBCDNString(retcert.getSubjectDN().getName());
                    if (mysubjectdn.equals(subjectdn)) {
                        log.info("Got user cert with DN: "+ retcert.getSubjectDN().getName());
                        // issued certificate
                        assertEquals(CertTools.stringToBCDNString("C=SE,O=PrimeKey,CN=sceptest"), subjectdn);
                        retcert.verify(cacert.getPublicKey());
                        assertTrue(checkKeys(keys.getPrivate(), retcert.getPublicKey()));
                        verified = true;
                        String altName = CertTools.getSubjectAlternativeName(retcert);
                        assertEquals("iPAddress=10.0.0.1, dNSName=foo.bar.com", altName);
                        usercert = retcert;
                    } else {
                    	log.info("Got CA cert with DN: "+ retcert.getSubjectDN().getName());
                        // ca certificate
                        assertEquals(cacert.getSubjectDN().getName(), retcert.getSubjectDN().getName());
                        gotcacert = true;
                        usercert.verify(retcert.getPublicKey());
                    }
                }
                assertTrue(verified);
                if (noca) {
                	assertFalse(gotcacert);
                } else {
                    assertTrue(gotcacert);                	
                }
            }
        }
        
    }
    /**
     * checks that a public and private key matches by signing and verifying a message
     */
    private boolean checkKeys(PrivateKey priv, PublicKey pub) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
        Signature signer = Signature.getInstance("SHA1WithRSA");
        signer.initSign(priv);
        signer.update("PrimeKey".getBytes());
        byte[] signature = signer.sign();
        
        Signature signer2 = Signature.getInstance("SHA1WithRSA");
        signer2.initVerify(pub);
        signer2.update("PrimeKey".getBytes());
        return signer2.verify(signature);
    }
    private byte[] sendScep(boolean post, byte[] scepPackage, boolean noca) throws IOException {
        // POST the OCSP request
        // we are going to do a POST
    	String resource = resourceScep;
    	if (noca) {
    		resource = resourceScepNoCA;
    	}
    	String urlString = httpReqPath + '/' + resource+"?operation=PKIOperation";
    	log.debug("UrlString =" + urlString);
        log.debug("scepPackage.length: " + scepPackage.length);
        HttpURLConnection con = null;
        if (post) {
            URL url = new URL(urlString);
            con = (HttpURLConnection)url.openConnection();
            con.setDoOutput(true);
            con.setRequestMethod("POST");
            con.connect();
            // POST it
            OutputStream os = con.getOutputStream();
            os.write(scepPackage);
            os.close();
        } else {
            String reqUrl = urlString + "&message=" + URLEncoder.encode(new String(Base64.encode(scepPackage)),"UTF-8");
            URL url = new URL(reqUrl);
            con = (HttpURLConnection)url.openConnection();
            con.setRequestMethod("GET");
            con.getDoOutput();
            con.connect();
        }
        log.debug("HTTP response message: " + con.getResponseMessage());
        assertEquals("Response code ", 200, con.getResponseCode());
        assertEquals("Content-Type", "application/x-pki-message", con.getContentType());
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // This works for small requests, and SCEP requests are small enough
        InputStream in = con.getInputStream();
        int b = in.read();
        while (b != -1) {
            baos.write(b);
            b = in.read();
        }
        baos.flush();
        in.close();
        byte[] respBytes = baos.toByteArray();
        assertNotNull("Response can not be null.", respBytes);
        assertTrue(respBytes.length > 0);                
        return respBytes;
    }
}
