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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JcaX509CertSelectorConverter;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;
import org.bouncycastle.x509.X509CertStoreSelector;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.util.CertTools;

/**
 * Class containing static help methods used to encrypt, decrypt, sign  and verify ExtRASubMessages
 * 
 * $Id$
 */
public class ExtRAMsgHelper {

    private static final Log log = LogFactory.getLog(ExtRAMsgHelper.class);
    private static ASN1ObjectIdentifier encAlg = NISTObjectIdentifiers.id_aes256_CBC; // default encryption algorithm
    private static String digestAlgorithm = CMSSignedGenerator.DIGEST_SHA256; // default signature digest
    private static String provider = BouncyCastleProvider.PROVIDER_NAME;
    
    /**
     * Method to initalize the helper class. Should be called before any of the methods are used
     * in not hte default values should be used.
     * 
     * @param encAlg encryption algorithm to use, must be supproted by the specified provider.
     * @prarm signAlg signature algorighm to use, must be supproted by the specified provider.
     */
    public static void init(String provider, ASN1ObjectIdentifier encAlg, String signAlg) {
        ExtRAMsgHelper.encAlg = encAlg;
        ExtRAMsgHelper.digestAlgorithm = signAlg;
        ExtRAMsgHelper.provider = provider;
    }

    /**
     * Method that should be used to encrypt data in a message.
     * 
     * Uses the algorithm specified in the init method.
     * 
     * @param encCert, the recepient to encrypt to.
     * @param data
     * @return encrypted byte[]
     * @throws IOException 
     */
    public static byte[] encryptData(X509Certificate encCert, byte[] data) throws IOException {

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        CMSEnvelopedData ed;
        try {
            edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(encCert).setProvider(provider));
            JceCMSContentEncryptorBuilder jceCMSContentEncryptorBuilder = new JceCMSContentEncryptorBuilder(encAlg).setProvider(provider);
            ed = edGen.generate(new CMSProcessableByteArray(data), jceCMSContentEncryptorBuilder.build());
        } catch (Exception e) {
            log.error("Error Encryotin Keys:: ", e);
            throw new IOException(e.getMessage());
        }

        return ed.getEncoded();
    }

    /**
     * Method that should be used to decrypt data in a message.
     * 
     * Uses the algorithm specified in the init method.
     * 
     * @param decKey, the recipients private key.
     * @param encData, the encrypted data
     * @return encrypted byte[] or null if decryption failed.
     */
    public static byte[] decryptData(PrivateKey decKey, byte[] encData) {
        byte[] retdata = null;
        try {
            CMSEnvelopedData ed = new CMSEnvelopedData(encData);

            RecipientInformationStore recipients = ed.getRecipientInfos();
            @SuppressWarnings("unchecked")
            Iterator<RecipientInformation> it = recipients.getRecipients().iterator();
            RecipientInformation recipient = (RecipientInformation) it.next();
            JceKeyTransEnvelopedRecipient rec = new JceKeyTransEnvelopedRecipient(decKey);
            rec.setProvider(provider);
            rec.setContentProvider(BouncyCastleProvider.PROVIDER_NAME);
            retdata = recipient.getContent(rec);
        } catch (Exception e) {
            log.error("Error decypting data : ", e);
        }

        return retdata;
    }

    /**
     * Method that signes the given data using the algorithm specified in the init method.
     * 
     * @param signKey, the key used to sign the data
     * @param signCert the certificate
     * @param data
     * @return the signed data or null if signature failed
     */
    public static byte[] signData(PrivateKey signKey, X509Certificate signCert, byte[] data) {
        byte[] retdata = null;
        try {
            ArrayList<X509Certificate> certList = new ArrayList<X509Certificate>();
            certList.add(signCert);
            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            gen.addCertificates(new CollectionStore(CertTools.convertToX509CertificateHolder(certList)));           
            String signatureAlgorithmName = AlgorithmTools.getAlgorithmNameFromDigestAndKey(digestAlgorithm, signKey.getAlgorithm());
            JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(signatureAlgorithmName).setProvider(provider);
            try {
                ContentSigner contentSigner = signerBuilder.build(signKey);
                JcaDigestCalculatorProviderBuilder calculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME);
                JcaSignerInfoGeneratorBuilder builder = new JcaSignerInfoGeneratorBuilder(calculatorProviderBuilder.build());
                gen.addSignerInfoGenerator(builder.build(contentSigner, signCert));
            } catch (OperatorCreationException e) {
                throw new IllegalStateException("BouncyCastle failed in creating signature provider.", e);
            }             
            CMSSignedData signedData = gen.generate(new CMSProcessableByteArray(data), true);
            retdata = signedData.getEncoded();
        } catch (Exception e) {
            log.error("Error signing data : ", e);
        }
        return retdata;
    }

    /**
     * Method used to verify signed data.
     * 
     * @param TrustedCACerts a Collection of trusted certifcates, should contain the entire chains
     * @param signedData the data to verify
     * @return true if signature verifes
     */
    public static ParsedSignatureResult verifySignature(Collection<Certificate> cACertChain, byte[] signedData) {
        return verifySignature(cACertChain, signedData, new Date());
    }

    /**
     * Method used to verify signed data.
     * 
     * @param TrustedCACerts a Collection of trusted certificates, should contain the entire chains
     * @param signedData the data to verify
     * @param date the date used to check the validity against.
     * @return a ParsedSignatureResult.
     */
    public static ParsedSignatureResult verifySignature(Collection<Certificate> cACertChain, byte[] signedData, Date date) {
        boolean verifies = false;
        X509Certificate usercert = null;
        ParsedSignatureResult retval = new ParsedSignatureResult(false, null, null);
        byte[] content = null;

        try {
            // First verify the signature
            CMSSignedData sp = new CMSSignedData(signedData);

            Store certs = sp.getCertificates();
            SignerInformationStore signers = sp.getSignerInfos();

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ((CMSProcessableByteArray) sp.getSignedContent()).write(baos);
            content = baos.toByteArray();
            baos.close();

            for (Object o : signers.getSigners()) {
                SignerInformation signer = (SignerInformation) o;
                JcaX509CertSelectorConverter conv = new JcaX509CertSelectorConverter();
                @SuppressWarnings("unchecked")
                List<X509CertificateHolder> certCollection = new ArrayList<X509CertificateHolder>(certs.getMatches(X509CertStoreSelector.getInstance(conv.getCertSelector(signer.getSID()))));
                usercert = new JcaX509CertificateConverter().getCertificate(certCollection.get(0));
                boolean validalg = signer.getDigestAlgOID().equals(digestAlgorithm);
                JcaDigestCalculatorProviderBuilder calculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME);
                JcaSignerInfoVerifierBuilder jcaSignerInfoVerifierBuilder = new JcaSignerInfoVerifierBuilder(calculatorProviderBuilder.build()).setProvider(BouncyCastleProvider.PROVIDER_NAME);      
                verifies = validalg && signer.verify(jcaSignerInfoVerifierBuilder.build(usercert.getPublicKey()));
            }

            // Second validate the certificate           
            X509Certificate rootCert = null;
            Iterator<Certificate> iter = cACertChain.iterator();
            while (iter.hasNext()) {
                X509Certificate cert = (X509Certificate) iter.next();
                if (cert.getIssuerDN().equals(cert.getSubjectDN())) {
                    rootCert = cert;
                    break;
                }
            }

            if (rootCert == null) {
                throw new CertPathValidatorException("Error Root CA cert not found in cACertChain");
            }

            List<Object> list = new ArrayList<Object>();
            list.add(usercert);
            list.add(cACertChain);

            CollectionCertStoreParameters ccsp = new CollectionCertStoreParameters(list);
            CertStore store = CertStore.getInstance("Collection", ccsp);

            //validating path
            List<Certificate> certchain = new ArrayList<Certificate>();
            certchain.addAll(cACertChain);
            certchain.add(usercert);
            CertPath cp = CertificateFactory.getInstance("X.509", "BC").generateCertPath(certchain);

            Set<TrustAnchor> trust = new HashSet<TrustAnchor>();
            trust.add(new TrustAnchor(rootCert, null));

            CertPathValidator cpv = CertPathValidator.getInstance("PKIX", "BC");
            PKIXParameters param = new PKIXParameters(trust);
            param.addCertStore(store);
            param.setDate(date);
            param.setRevocationEnabled(false);      
            cpv.validate(cp, param);
            retval = new ParsedSignatureResult(verifies, usercert, content);
        } catch (Exception e) {
            log.error("Error verifying data : ", e);
        }

        return retval;
    }

}
