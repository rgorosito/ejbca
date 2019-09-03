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
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;

import org.apache.log4j.Logger;
import org.cesecore.keys.token.p11ng.CK_CP5_AUTH_DATA;
import org.cesecore.keys.token.p11ng.CK_CP5_INITIALIZE_PARAMS;
import org.cesecore.keys.token.p11ng.provider.CryptokiDevice;
import org.cesecore.keys.token.p11ng.provider.CryptokiManager;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;
import org.ejbca.ui.p11ngcli.helper.P11NgCliHelper;
import org.pkcs11.jacknji11.CEi;
import org.pkcs11.jacknji11.CKA;
import org.pkcs11.jacknji11.CKM;
import org.pkcs11.jacknji11.CKR;
import org.pkcs11.jacknji11.CKRException;
import org.pkcs11.jacknji11.CKU;
import org.pkcs11.jacknji11.CK_SESSION_INFO;
import org.pkcs11.jacknji11.LongRef;

import com.sun.jna.Memory;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;

/**
 * Class implementing the key authorization init command for P11Ng CLI tool.
 * This command is CP5 specific.
 * 
 * @version $Id$
 *
 */
public class P11NgCliKeyAuthorizationInitCommand extends P11NgCliCommandBase {
    
    private static final Logger log = Logger.getLogger(P11NgCliKeyAuthorizationInitCommand.class);

    private static final String LIBFILE = "-libfile";
    private static final String SLOT = "-slot";
    private static final String ALIAS = "-alias";
    private static final String KAK_FILE_PATH = "-kak_file_path";
    private static final String USER_AND_PIN = "-user_and_pin";

    private static final int KEY_AUTHORIZATION_ASSIGNED = 1;
    private static final int KAK_PUBLIC_EXP_BUF_SIZE = 3;
    
    private static CEi ce;

    
    //Register all parameters
    {
        registerParameter(
                new Parameter(LIBFILE, "lib file", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, "Shared library path"));
        registerParameter(new Parameter(SLOT, "HSM slot", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "Slot on the HSM which will be used."));
        registerParameter(
                new Parameter(ALIAS, "alias", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, 
                        "Alias of the key pair on the HSM."));
        registerParameter(
                new Parameter(KAK_FILE_PATH, "KAK file path", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                        "The path which will be used to save the KAK file to and later for authorization the KAK will be read from it."));
        registerParameter(
                new Parameter(USER_AND_PIN, "User name and pin ", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                        "This option is used to provide user cridential for running the CP5 command."));
    }
    
    
    @Override
    public String getMainCommand() {
        return "keyauthorizationinit";
    }

    @Override
    public String getCommandDescription() {
        return "Initializes a key prior to authorization.";
    }

    @Override
    protected CommandResult execute(ParameterContainer parameters) {
        final long slotId = Long.parseLong(parameters.get(SLOT));
        final String alias = parameters.get(ALIAS);
        final String kakFilePath = parameters.get(KAK_FILE_PATH);
        
        final File library = new File(parameters.get(LIBFILE));
        final String libDir = library.getParent();
        final String libName = library.getName();
        CryptokiDevice device = CryptokiManager.getInstance().getDevice(libName, libDir);
        CryptokiDevice.Slot slot = device.getSlot(slotId);
        
        // KAK generation part
        KeyPair kakPair = generateKeyPair(); 
        Key kakPublicKey = kakPair.getPublic();
        Key kakPrivateKey = kakPair.getPrivate();

        // Saving the private key, later it will be used in key authorization section.
        try { 
            savePrivateKey(kakFilePath, kakPrivateKey);
        } catch (IOException e) {
            log.error("IOException happened while saving the kak private key on the disk!", e);
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        
        RSAPublicKeySpec publicSpec = (RSAPublicKeySpec) generateKeySpec(kakPublicKey);
        BigInteger kakPublicExponent  = publicSpec.getPublicExponent();
        BigInteger kakModulus = publicSpec.getModulus();
        
        byte[] kakModBuf = new byte[P11NgCliHelper.bitsToBytes(P11NgCliHelper.KAK_SIZE)];
        byte[] kakPubExpBuf = new byte[KAK_PUBLIC_EXP_BUF_SIZE];
        
        int kakModLen = kakModulus.toByteArray().length;
        int kakPubExpLen = kakPublicExponent.toByteArray().length;

        assert(kakModBuf.length >= kakModLen);
        assert(kakPubExpBuf.length >= kakPubExpLen);
        
        kakModBuf = kakModulus.toByteArray();
        kakPubExpBuf = kakPublicExponent.toByteArray();

        CK_CP5_INITIALIZE_PARAMS params = new CK_CP5_INITIALIZE_PARAMS();
        CK_CP5_AUTH_DATA authData = new CK_CP5_AUTH_DATA();
        authData.ulModulusLen = new NativeLong(kakModLen);
        
        // allocate sufficient native memory to hold the java array Pointer ptr = new Memory(arr.length);
        // Copy the java array's contents to the native memory ptr.write(0, arr, 0, arr.length);
        Pointer kakModulusPointer = new Memory(kakModLen);
        kakModulusPointer.write(0, kakModBuf, 0, kakModLen);
        authData.pModulus = kakModulusPointer;
        authData.ulPublicExponentLen = new NativeLong(kakPubExpLen);
        
        Pointer kakPublicKeyExponentPointer = new Memory(kakPubExpLen);
        kakPublicKeyExponentPointer.write(0, kakPubExpBuf, 0, kakPubExpLen);
        authData.pPublicExponent = kakPublicKeyExponentPointer;
        authData.protocol = (byte) CKM.CP5_KEY_AUTH_PROT_RSA_PSS_SHA256;

        params.authData = authData;
        params.bAssigned = KEY_AUTHORIZATION_ASSIGNED;

        long session = ce.OpenSession(slotId, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
        ce.Login(session, CKU.CKU_CS_GENERIC, parameters.get(USER_AND_PIN).getBytes(StandardCharsets.UTF_8));
        
        params.write(); // Write data before passing structure to function
        CKM mechanism = new CKM(CKM.CKM_CP5_INITIALIZE, params.getPointer(), params.size());
        
        byte[] hash = new byte[P11NgCliHelper.HASH_SIZE];
        long hashLen = hash.length;

        // Get the private key from HSM
        long[] privateKeyObjects = getPrivateKeyFromHSM(slot, alias);
        
        long rvAuthorizeKeyInit = ce.authorizeKeyInit(session, mechanism, privateKeyObjects[0], hash, new LongRef(hashLen));
        if (rvAuthorizeKeyInit != CKR.OK) {
            P11NgCliHelper.cleanUp(ce, session);
            throw new CKRException(rvAuthorizeKeyInit);
        }

        byte[] initSig = new byte[P11NgCliHelper.bitsToBytes(P11NgCliHelper.KAK_SIZE)];
        try {
            initSig = P11NgCliHelper.signHashPss(hash, hashLen, initSig.length, kakPrivateKey);
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException 
                 | InvalidAlgorithmParameterException | SignatureException e) {
            log.error("Error happened while signing the hash!", e);
        }

        long rvAuthorizeKey = ce.authorizeKey(session, initSig, initSig.length);
        if (rvAuthorizeKey != CKR.OK) {
            P11NgCliHelper.cleanUp(ce, session);
            throw new CKRException(rvAuthorizeKey);
        }
        P11NgCliHelper.cleanUp(ce, session);
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
    
    private KeyPair generateKeyPair() {
        KeyPairGenerator kpg = null;
        try {
            kpg = KeyPairGenerator.getInstance("RSA", "BC");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            log.error("Error happened while generationg the key pair!", e);
        }
        kpg.initialize(P11NgCliHelper.KAK_SIZE);
        return kpg.generateKeyPair();
    }
    
    private void savePrivateKey(final String path, final Key privateKey) throws IOException {
        final Path pathToKeyDirectory = Paths.get(path);

        if(Files.notExists(pathToKeyDirectory)){
            log.info("Target directory \"" + path + "\" will be created.");
            Files.createDirectories(pathToKeyDirectory);
        }
        // Store Private Key.
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
                privateKey.getEncoded());
        
        final Path pathToPrivateKey = Paths.get(pathToKeyDirectory.toString() + "/privateKey");
        Files.write(pathToPrivateKey, pkcs8EncodedKeySpec.getEncoded());
    }
    
    private long[] getPrivateKeyFromHSM(CryptokiDevice.Slot slot, final String alias) {
        // Get the private key from HSM
        long[] privateKeyObjects = slot.findPrivateKeyObjectsByID(slot.aquireSession(), new CKA(CKA.ID, alias.getBytes(StandardCharsets.UTF_8)).getValue());
        if (privateKeyObjects.length == 0) {
            throw new IllegalStateException("No private key found for alias '" + alias + "'");
        }
        if (log.isDebugEnabled()) {
            log.debug("Private key  with Id: '" + privateKeyObjects[0] + "' found for key alias '" + alias + "'");
        }
        return privateKeyObjects;
    }
    
    
    private KeySpec generateKeySpec(final Key key) {
        KeyFactory kf = null;
        KeySpec spec = null;
        try {
            kf = KeyFactory.getInstance("RSA");
            spec = kf.getKeySpec(key, KeySpec.class);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            log.error("Error happened while getting the key spec!", e);
        }
        return spec;
    }
}
