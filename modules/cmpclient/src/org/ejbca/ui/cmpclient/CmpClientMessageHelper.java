/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.cmpclient;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Random;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.lang.StringUtils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.PBMParameter;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.util.CertTools;
import org.ejbca.config.CmpConfiguration;

public class CmpClientMessageHelper {
    
    public static CmpClientMessageHelper getInstance() {
        return new CmpClientMessageHelper();
    }
    
    public PKIMessage createProtectedMessage(PKIMessage pkimessage, String authModule, String authParameter, 
            final String keystorePath, final String keystorepwd, final boolean verbose) throws InvalidKeyException, NoSuchAlgorithmException, 
            NoSuchProviderException, UnrecoverableKeyException, KeyStoreException, CertificateException, 
            FileNotFoundException, IOException, SecurityException, SignatureException {
        

        
        if(StringUtils.equalsIgnoreCase(authModule, CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD)) {
            if(verbose) {
                System.out.println("Authentication module used is " + CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD + ". " +
                		"PKI message returned as is.");
            }
            return pkimessage;
        }
        
        if(StringUtils.equalsIgnoreCase(authModule, CmpConfiguration.AUTHMODULE_HMAC)) {
            if(verbose) {
                System.out.println("Creating protected PKIMessage using: authentication module="+authModule + ", authentication parameter="+authParameter);
            }
            return protectPKIMessageWithHMAC(pkimessage, false, authParameter, 567);
        }
        
        if(StringUtils.equalsIgnoreCase(authModule, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE)) {
            if(verbose) {
                System.out.println("Creating protected PKIMessage using authentication module: " + authModule);
                System.out.println("Certificate in extraCerts field should be issued by: " + authParameter);
                System.out.println("Keystore: " + keystorePath + "  -  Keystore password: " + keystorepwd);
            }
            
            final KeyStore keystore = getKeystore(keystorePath, keystorepwd);
            Certificate extraCert = getCertFromKeystore(keystore, authParameter);
            //Object[] adminData = getAdminDataFromKeystore(keystore, keystorepwd, authParameter, verbose);
            //Certificate adminCert = (Certificate) adminData[0];
            if(verbose) {
                System.out.println("Certificate to be attached in the extraCerts field extracted from keystore. " +
                		"Certificate SubjectDN: " + CertTools.getSubjectDN(extraCert) + " - Certificate issuerDN: " + CertTools.getIssuerDN(extraCert) + " - " +
                		"Certificate serialnumber: " + CertTools.getSerialNumberAsString(extraCert) + " - Certificate fingerprint: " + CertTools.getFingerprintAsString(extraCert));
            }
            
            PrivateKey signKey = (PrivateKey) getKeyFromKeystore(keystore, keystorepwd, authParameter);
            
            CMPCertificate[] extraCerts = getCMPCerts(extraCert);
            AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
            return buildCertBasedPKIProtection(pkimessage, extraCerts, signKey, pAlg.getAlgorithm().getId(), "BC", verbose);
        }
        
        System.out.println("Unrecognized authentication module: " + authModule);
        return null;
    }
    
    private PKIMessage protectPKIMessageWithHMAC(PKIMessage msg, boolean badObjectId, String password, int iterations)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        // Create the PasswordBased protection of the message
        PKIHeaderBuilder head = getHeaderBuilder(msg.getHeader());
        // SHA1
        AlgorithmIdentifier owfAlg = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.3.14.3.2.26"));
        // 567 iterations
        int iterationCount = iterations;
        ASN1Integer iteration = new ASN1Integer(iterationCount);
        // HMAC/SHA1
        AlgorithmIdentifier macAlg = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.2.7"));
        byte[] salt = "foo123".getBytes();
        DEROctetString derSalt = new DEROctetString(salt);

        // Create the new protected return message
        String objectId = "1.2.840.113533.7.66.13";
        if (badObjectId) {
            objectId += ".7";
        }
        PBMParameter pp = new PBMParameter(derSalt, owfAlg, iteration, macAlg);
        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(new ASN1ObjectIdentifier(objectId), pp);
        head.setProtectionAlg(pAlg);
        PKIHeader header = head.build();
        // Calculate the protection bits
        byte[] raSecret = password.getBytes();
        byte[] basekey = new byte[raSecret.length + salt.length];
        System.arraycopy(raSecret, 0, basekey, 0, raSecret.length);
        for (int i = 0; i < salt.length; i++) {
            basekey[raSecret.length + i] = salt[i];
        }
        // Construct the base key according to rfc4210, section 5.1.3.1
        MessageDigest dig = MessageDigest.getInstance(owfAlg.getAlgorithm().getId(), "BC");
        for (int i = 0; i < iterationCount; i++) {
            basekey = dig.digest(basekey);
            dig.reset();
        }
        // For HMAC/SHA1 there is another oid, that is not known in BC, but the
        // result is the same so...
        String macOid = macAlg.getAlgorithm().getId();
        PKIBody body = msg.getBody();
        byte[] protectedBytes = getProtectedBytes(header, body);
        Mac mac = Mac.getInstance(macOid, "BC");
        SecretKey key = new SecretKeySpec(basekey, macOid);
        mac.init(key);
        mac.reset();
        mac.update(protectedBytes, 0, protectedBytes.length);
        byte[] out = mac.doFinal();
        DERBitString bs = new DERBitString(out);
        
        return new PKIMessage(header, body, bs);
    }
    
    private PKIHeaderBuilder getHeaderBuilder(PKIHeader head) {
        PKIHeaderBuilder builder = new PKIHeaderBuilder(head.getPvno().getValue().intValue(), head.getSender(), head.getRecipient());
        builder.setFreeText(head.getFreeText());
        builder.setGeneralInfo(head.getGeneralInfo());
        builder.setMessageTime(head.getMessageTime());
        builder.setRecipKID((DEROctetString) head.getRecipKID());
        builder.setRecipNonce(head.getRecipNonce());
        builder.setSenderKID(head.getSenderKID());
        builder.setSenderNonce(head.getSenderNonce());
        builder.setTransactionID(head.getTransactionID());
        return builder;
    }
    
    /**
     * Converts the header and the body of a PKIMessage to an ASN1Encodable and 
     * returns the as a byte array
     *  
     * @param header
     * @param body
     * @return the PKIMessage's header and body in byte array
     */
    private byte[] getProtectedBytes(PKIHeader header, PKIBody body) {
        byte[] res = null;
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(header);
        v.add(body);
        ASN1Encodable protectedPart = new DERSequence(v);
        try {
            ByteArrayOutputStream bao = new ByteArrayOutputStream();
            DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(protectedPart);
            res = bao.toByteArray();
        } catch (Exception ex) {
            System.out.println(ex.getLocalizedMessage());
            ex.printStackTrace();
        }
        return res;
    }
    
    
    
    
    
    
    private PKIMessage buildCertBasedPKIProtection(PKIMessage pKIMessage, CMPCertificate[] extraCerts, PrivateKey key, String digestAlg,
            String provider, boolean verbose) throws NoSuchProviderException, NoSuchAlgorithmException, SecurityException, SignatureException, InvalidKeyException {
        // Select which signature algorithm we should use for the response, based on the digest algorithm and key type.
        ASN1ObjectIdentifier oid = AlgorithmTools.getSignAlgOidFromDigestAndKey(digestAlg, key.getAlgorithm());
        if(verbose) {
        System.out.println("Selected signature alg oid: " + oid.getId()+", key algorithm: "+key.getAlgorithm());
        }
        // According to PKCS#1 AlgorithmIdentifier for RSA-PKCS#1 has null Parameters, this means a DER Null (asn.1 encoding of null), not Java null.
        // For the RSA signature algorithms specified above RFC3447 states "...the parameters MUST be present and MUST be NULL."
        PKIHeaderBuilder headerBuilder = getHeaderBuilder(pKIMessage.getHeader());
        AlgorithmIdentifier pAlg = null;
        if ("RSA".equalsIgnoreCase(key.getAlgorithm())) {
            pAlg = new AlgorithmIdentifier(oid, DERNull.INSTANCE);
        } else {
            pAlg = new AlgorithmIdentifier(oid);
        }
        headerBuilder.setProtectionAlg(pAlg);
        // Most PKCS#11 providers don't like to be fed an OID as signature algorithm, so 
        // we use BC classes to translate it into a signature algorithm name instead
        PKIHeader head = headerBuilder.build();
        String signatureAlgorithmName = AlgorithmTools.getAlgorithmNameFromOID(oid);
        if(verbose) {
            System.out.println("Signing CMP message with signature alg: " + signatureAlgorithmName);
        }
        Signature sig = Signature.getInstance(signatureAlgorithmName, provider);
        sig.initSign(key);
        sig.update(getProtectedBytes(head, pKIMessage.getBody()));

        if ((extraCerts != null) && (extraCerts.length > 0)) {
            pKIMessage = new PKIMessage(head, pKIMessage.getBody(), new DERBitString(sig.sign()), extraCerts);
        } else {
            pKIMessage = new PKIMessage(head, pKIMessage.getBody(), new DERBitString(sig.sign()));
        }
        return pKIMessage;
    }
    
    private KeyStore getKeystore(final String keystorePath, final String keystorePassword) 
            throws NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, KeyStoreException {
        KeyStore keystore = KeyStore.getInstance("PKCS12");
        keystore.load(new FileInputStream(keystorePath), keystorePassword.toCharArray());
        return keystore;
    }
    
    private Certificate getCertFromKeystore(final KeyStore keystore, final String alias) throws KeyStoreException {
        Certificate cert = keystore.getCertificate(alias);
        if(cert==null) {
            System.err.println("getAdminDataFromKeystore: Cannot obtain admin certificate from the keystore.");
            System.exit(2);
        }
        return cert;
    }
    
    private Key getKeyFromKeystore(final KeyStore keystore, final String keystorepwd, final String alias) 
            throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
        Key key = keystore.getKey(alias, keystorepwd.toCharArray());
        if(key==null) {
            System.err.println("getAdminDataFromKeystore: Cannot obtain admin key from the keystore.");
            System.exit(2);
        }
        return key;
    }
/*    
    private Object[] getAdminDataFromKeystore(final String keystorePath, final String keystorePassword, final String extraCertsFriendlyName, 
            boolean verbose) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, 
            IOException, UnrecoverableKeyException {
        KeyStore keystore = KeyStore.getInstance("PKCS12");
        keystore.load(new FileInputStream(keystorePath), keystorePassword.toCharArray());

        if(verbose) {
            System.out.println("getAdminDataFromKeystore: Getting certificate with friendlyname: " + extraCertsFriendlyName);
        }
        
        Certificate adminCert = keystore.getCertificate(extraCertsFriendlyName);
        Key adminKey = keystore.getKey(extraCertsFriendlyName, keystorePassword.toCharArray());
        
        if(adminCert==null) {
            System.err.println("getAdminDataFromKeystore: Cannot obtain admin certificate from the keystore.");
            System.exit(2);
        }
        if(adminKey==null) {
            System.err.println("getAdminDataFromKeystore: Cannot obtain admin key from the keystore.");
            System.exit(2);
        }
        Object[] adminData = {adminCert, adminKey};
        return adminData;
    }
*/    
    private CMPCertificate[] getCMPCerts(Certificate cert) throws CertificateEncodingException, IOException {
        ASN1InputStream ins = new ASN1InputStream(cert.getEncoded());
        ASN1Primitive pcert = ins.readObject();
        ins.close();
        org.bouncycastle.asn1.x509.Certificate c = org.bouncycastle.asn1.x509.Certificate.getInstance(pcert.toASN1Primitive());
        CMPCertificate[] res = {new CMPCertificate(c)};
        return res;
    }
    
    
    
    public byte[] getRequestBytes(PKIMessage pkimessage) throws IOException {
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(pkimessage);
        byte[] ba = bao.toByteArray();
        return ba;  
    }
    
    public byte[] sendCmpHttp(final byte[] message, final int httpRespCode, final String cmpAlias, final String host) throws IOException {
        
        final String httpReqPath = "http://" + host + ":8080/ejbca";
        final String resourceCmp = "publicweb/cmp";
        
        // POST the CMP request
        // we are going to do a POST
        final String urlString = httpReqPath + '/' + resourceCmp + '/' + cmpAlias;
        System.out.println("CMP URL: " + urlString);
        URL url = new URL(urlString);
        final HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setDoOutput(true);
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-type", "application/pkixcmp");
        con.connect();
        // POST it
        OutputStream os = con.getOutputStream();
        os.write(message);
        os.close();

        final int conResponseCode = con.getResponseCode();
        if(conResponseCode != httpRespCode) {
            System.out.println("Unexpected HTTP response code: " + conResponseCode);
        }
        // Only try to read the response if we expected a 200 (ok) response
        if (httpRespCode != 200) {
            return null;
        }
        // Some appserver (Weblogic) responds with
        // "application/pkixcmp; charset=UTF-8"
        final String conContentType = con.getContentType();
        if(conContentType == null) {
            System.out.println("No content type in response.");
            System.exit(1);
        }
        if(!StringUtils.equals("application/pkixcmp", conContentType)) {
            System.out.println("Content type is not 'application/pkixcmp'");
        }
        // Check that the CMP respone has the cache-control headers as specified in 
        // http://tools.ietf.org/html/draft-ietf-pkix-cmp-transport-protocols-14
        final String cacheControl = con.getHeaderField("Cache-Control");
        if(cacheControl == null) {
            System.out.println("'Cache-Control' header is not present.");
            System.exit(1);
        }
        if(!StringUtils.equals("no-cache", cacheControl)) {
            System.out.println("Cache-Control is not 'no-cache'");
            System.exit(1);
        }
        final String pragma = con.getHeaderField("Pragma");
        if(pragma == null) {
            System.out.println("'Pragma' header is not present.");
            System.exit(1);
        }
        if(!StringUtils.equals("no-cache", pragma)) {
            System.out.println("Pragma is not 'no-cache'");
            System.exit(1);
        }
        // Now read in the bytes
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // This works for small requests, and CMP requests are small enough
        InputStream in = con.getInputStream();
        int b = in.read();
        while (b != -1) {
            baos.write(b);
            b = in.read();
        }
        baos.flush();
        in.close();
        byte[] respBytes = baos.toByteArray();
        if((respBytes == null) || (respBytes.length <= 0)) {
            System.out.println("No response from server");
            System.exit(1);
        }
        return respBytes;
    }
    
    /** Creates a 16 bytes random sender nonce
     * 
     * @return byte array of length 16
     */
    public byte[] createSenderNonce() {
        // Sendernonce is a random number
        byte[] senderNonce = new byte[16];
        Random randomSource;
        randomSource = new Random();
        randomSource.nextBytes(senderNonce);
        return senderNonce;
    }
    
    
    
    
    
    
    
    
    
}
