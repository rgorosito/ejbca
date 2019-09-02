package org.ejbca.ui.p11ngcli.command;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import org.apache.log4j.Logger;
import org.cesecore.keys.token.p11ng.CK_CP5_AUTHORIZE_PARAMS;
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
import org.pkcs11.jacknji11.CKM;
import org.pkcs11.jacknji11.CKR;
import org.pkcs11.jacknji11.CKRException;
import org.pkcs11.jacknji11.CKU;
import org.pkcs11.jacknji11.CK_SESSION_INFO;
import org.pkcs11.jacknji11.LongRef;

public class P11NgCliKeyAuthorizationCommand extends P11NgCliCommandBase {
    
    private static final Logger log = Logger.getLogger(P11NgCliKeyAuthorizationCommand.class);
    
    private static final String SLOT = "-slot";
    private static final String ALIAS = "-alias";
    private static final String KAK_FILE_PATH = "-kak_file_path";
    private static final String LIBFILE = "-libfile";
    private static final String USER_AND_PIN = "-user_and_pin";

    private static long AUTH_CTR = 4294967295L; // Max Operations Number for the key, default is unlimited 

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
        return "keyauthorization";
    }

    @Override
    public String getCommandDescription() {
        return "Authorizes a key before it can be used.";
    }

    @Override
    protected CommandResult execute(ParameterContainer parameters) {
        final long slotId = Long.parseLong(parameters.get(SLOT));
        final File library = new File(parameters.get(LIBFILE));
        final String libDir = library.getParent();
        final String libName = library.getName();
        CryptokiDevice device = CryptokiManager.getInstance().getDevice(libName, libDir);
        CryptokiDevice.Slot slot = device.getSlot(slotId);
        
        final String alias = parameters.get(ALIAS);
        final String kakFilePath = parameters.get(KAK_FILE_PATH);
        
        CK_CP5_AUTHORIZE_PARAMS params = new CK_CP5_AUTHORIZE_PARAMS();
        
        params.ulCount = AUTH_CTR;
        
        params.write(); // Write data before passing structure to function
        CKM mechanism = new CKM(CKM.CKM_CP5_AUTHORIZE, params.getPointer(), params.size());

        byte[] hash = new byte[P11NgCliHelper.HASH_SIZE];
        long hashLen = hash.length;
        
        long session = ce.OpenSession(slotId, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
        ce.Login(session, CKU.CKU_CS_GENERIC, parameters.get(USER_AND_PIN).getBytes(StandardCharsets.UTF_8));
        
        long[] privateKeyObjects = P11NgCliHelper.getPrivateKeyFromHSM(slot, alias);
        
        long rvAuthorizeKeyInit = ce.authorizeKeyInit(session, mechanism, privateKeyObjects[0], hash, new LongRef(hashLen));
        if (rvAuthorizeKeyInit != CKR.OK) {
            P11NgCliHelper.cleanUp(ce, session);
            throw new CKRException(rvAuthorizeKeyInit);
        }
        
        // Here obtain the private key created in the previous init part, reading it from file
        Key kakPrivateKey = null;
        try {
            kakPrivateKey = loadPrivateKey(kakFilePath, "RSA");
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            log.error("Error happened while loading the kak key pair from disk!", e);
            return CommandResult.FUNCTIONAL_FAILURE;
        }

        byte[] authSig = new byte[P11NgCliHelper.bitsToBytes(P11NgCliHelper.KAK_SIZE)];
        try {
            authSig = P11NgCliHelper.signHashPss(hash, hashLen, authSig.length, kakPrivateKey);
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException 
                 | InvalidAlgorithmParameterException | SignatureException e) {
            log.error("Error happened while signing the hash!", e);
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        
        long rvAuthorizeKey = ce.authorizeKey(session, authSig, authSig.length);
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
    
    private Key loadPrivateKey(final String path, final String algorithm)
            throws IOException, NoSuchAlgorithmException,
            InvalidKeySpecException {
 
        // Read Private Key.
        File filePrivateKey = new File(path + "/privateKey");
        byte[] encodedPrivateKey = null;
        try (FileInputStream fis = new FileInputStream(path + "/privateKey")) {
            encodedPrivateKey = new byte[(int) filePrivateKey.length()];
            fis.read(encodedPrivateKey);
        }
 
        // Generate KeyPair.
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
 
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
                encodedPrivateKey);
        return keyFactory.generatePrivate(privateKeySpec);
    }

}
