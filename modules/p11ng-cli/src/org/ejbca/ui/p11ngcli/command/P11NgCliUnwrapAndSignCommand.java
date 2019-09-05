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
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.keys.token.p11ng.provider.CryptokiDevice;
import org.cesecore.keys.token.p11ng.provider.CryptokiManager;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;
import org.pkcs11.jacknji11.CEi;
import org.pkcs11.jacknji11.CKA;
import org.pkcs11.jacknji11.CKK;
import org.pkcs11.jacknji11.CKM;
import org.pkcs11.jacknji11.CKO;
import org.pkcs11.jacknji11.CKU;
import org.pkcs11.jacknji11.CK_SESSION_INFO;

/**
 * Class implementing the unwrap and sign command for P11Ng CLI tool.
 * 
 * @version $Id$
 *
 */
public class P11NgCliUnwrapAndSignCommand extends P11NgCliCommandBase {

    private static final Logger log = Logger.getLogger(P11NgCliUnwrapAndSignCommand.class);

    private static final String LIBFILE = "-libfile";
    private static final String SLOT = "-slot";
    private static final String PIN = "-pin";
    private static final String METHOD = "-method";
    private static final String UNWRAPKEY = "-unwrapkey";
    private static final String PRIVATEKEY = "-privatekey";
    private static final String PUBLICKEY = "-publickey";
    private static final String PLAINTEXT = "-plaintext";
    
    private static CEi ce;

    //Register all parameters
    {
        registerParameter(
                new Parameter(LIBFILE, "lib file", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, "Shared library path"));
        registerParameter(new Parameter(SLOT, "HSM slot", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "Slot on the HSM which will be used."));
        registerParameter(
                new Parameter(PIN, "PIN for the slot", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, 
                        "The pin which is used to connect to HSM slot."));
        registerParameter(
                new Parameter(METHOD, "method", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, 
                        "Method to use, either pkcs11 (default) or provider"));
        registerParameter(
                new Parameter(UNWRAPKEY, "unwrap key", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, 
                        "Label of key to unwrap with"));
        registerParameter(
                new Parameter(PRIVATEKEY, "private key", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, 
                        "base64 encoded encrypted (wrapped) private key"));
        registerParameter(
                new Parameter(PUBLICKEY, "public key", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, 
                        "base64 encoded public key"));
        registerParameter(
                new Parameter(PLAINTEXT, "plain text", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, 
                        "text string to sign"));
    }
    
    
    private static enum Method {
        pkcs11,
        provider
    }

    @Override
    public String getMainCommand() {
        return "unwrapandsignkey";
    }

    @Override
    public String getCommandDescription() {
        return "Unwraps and signs keys.";
    }

    @Override
    protected CommandResult execute(ParameterContainer parameters) {
        final long slotId = Long.parseLong(parameters.get(SLOT));
        final String unwrapkey = parameters.get(UNWRAPKEY);
        final String wrapped = parameters.get(PRIVATEKEY);
        final String publickey = parameters.get(PUBLICKEY);
        final String plaintext = parameters.get(PLAINTEXT);
        final File library = new File(parameters.get(LIBFILE));
        final String libDir = library.getParent();
        final String libName = library.getName();
        try {
            RSAPublicKey rsa = RSAPublicKey.getInstance(new ASN1InputStream(Base64.decode(publickey.getBytes())).readObject());
            PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(rsa.getModulus(), rsa.getPublicExponent()));

            if (!StringUtils.isBlank(parameters.get(METHOD)) && Method.valueOf(parameters.get(METHOD)) == Method.provider) {
                unwrapAndSignUsingProvider(libName, libDir, slotId, parameters.get(PIN), unwrapkey, wrapped, plaintext, publicKey);
            } else {
                unwrapAndSignUsingPKCS11(slotId, parameters.get(PIN), unwrapkey, wrapped, plaintext, publicKey);
            }

        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException | InvalidKeySpecException
                | IOException ex) {
            log.error("unwrapAndSign failed:", ex);
            System.err.println("unwrapAndSign failed: " + ex.getMessage());
            return CommandResult.FUNCTIONAL_FAILURE;
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
    
    private void unwrapAndSignUsingProvider(final String libName, final String libDir, final long slotId, final String pin, final String unwrapkey, final String wrapped, final String plaintext, final PublicKey publicKey) throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, NoSuchProviderException {
        log.debug("Using provider");
        CryptokiDevice device = CryptokiManager.getInstance().getDevice(libName, libDir);
        CryptokiDevice.Slot slot = device.getSlot(slotId);
        slot.login(pin);

        PrivateKey privateKey = null;
        try {
            privateKey = slot.unwrapPrivateKey(Base64.decode(wrapped), unwrapkey, CKM.AES_CBC_PAD);

            Signature sig1 = Signature.getInstance("SHA256withRSA", device.getProvider());
            sig1.initSign(privateKey);
            sig1.update(plaintext.getBytes());
            byte[] signed = sig1.sign();
            System.out.println("signed: " + new String(Base64.encode(signed)));

            Security.addProvider(new BouncyCastleProvider());

            Signature sig2 = Signature.getInstance("SHA256withRSA", "BC");
            sig2.initVerify(publicKey);
            sig2.update(plaintext.getBytes());
            System.out.println("Consistent: " + sig2.verify(signed));
            System.out.println();
        } finally {
            if (privateKey != null) {
                slot.releasePrivateKey(privateKey);
            }
        }
    }
    
    private void unwrapAndSignUsingPKCS11(final long slotId, final String pin, final String unwrapkey, final String wrapped, final String plaintext, final PublicKey publicKey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        log.debug("Using p11");
        
        ce.Initialize();
        long session = ce.OpenSession(slotId, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
        ce.Login(session, CKU.USER, pin.getBytes());   

        // Find unWrapKey
        long[] secretObjects = ce.FindObjects(session, new CKA(CKA.CLASS, CKO.SECRET_KEY));
        long unWrapKey = -1;
        for (long object : secretObjects) {
            CKA ckaLabel = ce.GetAttributeValue(session, object, CKA.LABEL);
            if (ckaLabel != null && unwrapkey.equals(ckaLabel.getValueStr())) {
                unWrapKey = object;
                break;
                }
        }
        if (unWrapKey < 0) {
            System.err.println("No such secret key found: " + unwrapkey);
            return;
        }

        CKA[] unwrappedPrivateKeyTemplate = new CKA[] {
            new CKA(CKA.CLASS, CKO.PRIVATE_KEY),
            new CKA(CKA.KEY_TYPE, CKK.RSA),
            new CKA(CKA.PRIVATE, true),
            new CKA(CKA.DECRYPT, true),
            new CKA(CKA.SIGN, true),
            new CKA(CKA.SENSITIVE, true),
            new CKA(CKA.EXTRACTABLE, true),
        };
        long privateKey = ce.UnwrapKey(session, new CKM(CKM.AES_CBC_PAD), unWrapKey, Base64.decode(wrapped), unwrappedPrivateKeyTemplate);
        System.out.println("Unwrapped key: " + privateKey);

        ce.SignInit(session, new CKM(CKM.SHA256_RSA_PKCS), privateKey);
        ce.SignUpdate(session, plaintext.getBytes());
        byte[] signed = ce.SignFinal(session);
        System.out.println("signed: " + new String(Base64.encode(signed)));

        Security.addProvider(new BouncyCastleProvider());

        Signature sig = Signature.getInstance("SHA256withRSA", "BC");
        sig.initVerify(publicKey);
        sig.update(plaintext.getBytes());
        System.out.println("Consistent: " + sig.verify(signed));
        System.out.println();
    }

}
