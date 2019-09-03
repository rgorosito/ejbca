/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.p11ngcli.command;

import java.io.File;
import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.util.Calendar;
import java.util.Date;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.RSAPublicKeyStructure;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.keys.token.p11ng.provider.CryptokiDevice;
import org.cesecore.keys.token.p11ng.provider.CryptokiManager;
import org.cesecore.keys.token.p11ng.provider.GeneratedKeyData;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.pkcs11.jacknji11.CKM;

public class P11NgCliGenerateAndWrapKeyPair extends P11NgCliCommandBase {
    
    private static final Logger log = Logger.getLogger(P11NgCliGenerateAndWrapKeyPair.class);

    private static final String SLOT = "-slot";
    private static final String ALIAS = "-alias";
    private static final String LIBFILE = "-libfile";
    private static final String PIN = "-pin";
    private static final String WRAPKEY = "-wrapkey";
    private static final String SELFCERT = "-selfcert";
    
    @Override
    public String getMainCommand() {
        return "generateandwrapkeypair";
    }

    @Override
    public String getCommandDescription() {
        return "Generates and wraps key pair.";
    }

    @Override
    protected CommandResult execute(ParameterContainer parameters) {
        final long slotId = Long.parseLong(parameters.get(SLOT));
        final String wrapkey = parameters.get(WRAPKEY);
        final boolean selfCert = Boolean.getBoolean(parameters.get(SELFCERT));
        final String alias = parameters.get(ALIAS);

        final File library = new File(parameters.get(LIBFILE));
        final String libDir = library.getParent();
        final String libName = library.getName();
        CryptokiDevice device = CryptokiManager.getInstance().getDevice(libName, libDir);
        CryptokiDevice.Slot slot = device.getSlot(slotId);
        slot.login(parameters.get(PIN));

        GeneratedKeyData generatedKeyData = slot.generateWrappedKey(wrapkey, "RSA", "2048", CKM.AES_CBC_PAD);

        // Converting java PublicKey to BC RSAPublicKey
        byte[] encoded = generatedKeyData.getPublicKey().getEncoded();
        SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(ASN1Sequence.getInstance(encoded));
        RSAPublicKey rsaPublicKey;
        try {
            byte[] rsaPublicKeyEncoded = subjectPublicKeyInfo.parsePublicKey().getEncoded();
            ASN1InputStream ais = new ASN1InputStream(rsaPublicKeyEncoded);
            Object asnObject = ais.readObject();
            ASN1Sequence sequence = (ASN1Sequence) asnObject;
            RSAPublicKeyStructure rsaPublicKeyStructure = new RSAPublicKeyStructure(sequence);
            rsaPublicKey = new RSAPublicKey(rsaPublicKeyStructure.getModulus(), rsaPublicKeyStructure.getPublicExponent());
            System.out.println("Public key: " + new String(Base64.encode(rsaPublicKey.getEncoded())));
        } catch (IOException ex) {
            log.error("IO error while generating wrapped key ", ex);
            System.err.println("IO error while generating wrapped key " + ex.getMessage());
            return CommandResult.FUNCTIONAL_FAILURE;
        }

        System.out.println("Wrapped private key: " + new String(Base64.encode(generatedKeyData.getWrappedPrivateKey())));

        if (selfCert) {
            PrivateKey privateKey = slot.unwrapPrivateKey(generatedKeyData.getWrappedPrivateKey(), wrapkey, CKM.AES_CBC_PAD);

            StringWriter out = new StringWriter();
            try {
                Calendar cal = Calendar.getInstance();
                Date notBefore = cal.getTime();
                cal.add(Calendar.YEAR, 50);
                Date notAfter = cal.getTime();

                X500Name dn = new X500Name("CN=Dummy cert for " + alias);
                X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(dn, new BigInteger("123"), notBefore, notAfter, dn,
                        generatedKeyData.getPublicKey());
                X509CertificateHolder cert = builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(privateKey));

                try (JcaPEMWriter writer = new JcaPEMWriter(out)) {
                    writer.writeObject(cert);
                }
                String pemCertificates = out.toString();

                System.out.println("Self signed certificate for generated wrapped key pair alias: " + alias);
                System.out.println(pemCertificates);
            } catch (IOException | OperatorCreationException ex) {
                log.error("Self signed certificate creation failed: ", ex);
                System.err.println("Self signed certificate creation failed: " + ex.getMessage());
                return CommandResult.FUNCTIONAL_FAILURE;
            } finally {
                if (privateKey != null) {
                    slot.releasePrivateKey(privateKey);
                }
            }
        }
        return CommandResult.SUCCESS;
    }

    @Override
    public String getFullHelpText() {
        return getCommandDescription();
    }

    @Override
    protected Logger getLogger() {
        return log;
    }

}
