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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.apache.log4j.Logger;
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
import org.pkcs11.jacknji11.CKU;
import org.pkcs11.jacknji11.CK_SESSION_INFO;

/**
 * 
 * @version $Id$
 *
 */
public class P11NgCliRestoreObjectCommand extends P11NgCliCommandBase {
    
    private static final Logger log = Logger.getLogger(P11NgCliRestoreObjectCommand.class);

    private static final String LIBFILE = "-libfile";
    private static final String SLOT = "-slot";
    private static final String USER_AND_PIN = "-user_and_pin";
    private static final String USER2_AND_PIN = "-user2_and_pin";
    private static final String BACKUPFILE = "-backupFile"; 
    private static final String OBJECT_SPEC_ID = "-object_spec_id";


    private static CEi ce;

    
    //Register all parameters
    {
        registerParameter(
                new Parameter(LIBFILE, "lib file", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, "Shared library path"));
        registerParameter(new Parameter(SLOT, "HSM slot", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "Slot on the HSM which will be used."));
        registerParameter(
                new Parameter(USER_AND_PIN, "User name and pin ", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                        "This option is used to provide user cridential for running the CP5 command."));
        registerParameter(
                new Parameter(USER2_AND_PIN, "User name 2 and pin", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                        "This option is used to provide user cridential for running the CP5 command (subset of them need two users)."));
        registerParameter(
                new Parameter(OBJECT_SPEC_ID, "object spec id", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, 
                        "idx of the key to back up"));        
        registerParameter(
                new Parameter(BACKUPFILE, "backup file", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, 
                        "full path to the file where backup bytes would be stored"));  
    }
    
    @Override
    public String getMainCommand() {
        return "restoreobject";
    }

    @Override
    public String getCommandDescription() {
        return "Restores a backed up key from file into the HSM. CP5 specific operation.";
    }

    @Override
    protected CommandResult execute(ParameterContainer parameters) {
        final long slotId = Long.parseLong(parameters.get(SLOT));
        final File library = new File(parameters.get(LIBFILE));
        final String libDir = library.getParent();
        final String libName = library.getName();
        final CryptokiDevice device = CryptokiManager.getInstance().getDevice(libName, libDir);
        device.getSlot(slotId); // Initialize slot
        ce = P11NgCliHelper.provideCe(parameters.get(LIBFILE));
        final long session = ce.OpenSession(slotId, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);                    
        ce.Login(session, CKU.CKU_CS_GENERIC, parameters.get(USER_AND_PIN).getBytes(StandardCharsets.UTF_8));
        ce.Login(session, CKU.CKU_CS_GENERIC, parameters.get(USER2_AND_PIN).getBytes(StandardCharsets.UTF_8));
        
        final Path filePath = Paths.get(parameters.get(BACKUPFILE));
        byte[] bytes;
        try {
            bytes = Files.readAllBytes(filePath);
        } catch (IOException e) {
            log.error("IOException while reading backup file.", e);
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        final long flags = 0; // alternative value here would be something called "CXI_KEY_FLAG_VOLATILE" but this causes 0x00000054: FUNCTION_NOT_SUPPORTED
        
        final long objectHandle = Long.parseLong(parameters.get(OBJECT_SPEC_ID));
        ce.restoreObject(session, flags, bytes, objectHandle);
        P11NgCliHelper.cleanUp(ce, session);
        return CommandResult.SUCCESS;
        /*
          CK_SESSION_HANDLE     hSession,
          CK_ULONG              flags,        
          CK_BYTE_PTR           pBackupObj,
          CK_ULONG              ulBackupObjLen,
          CK_OBJECT_HANDLE_PTR  phObject
         */
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
