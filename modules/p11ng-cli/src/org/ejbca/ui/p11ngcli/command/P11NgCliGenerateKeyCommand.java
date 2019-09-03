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

import org.apache.log4j.Logger;
import org.cesecore.keys.token.p11ng.provider.CryptokiDevice;
import org.cesecore.keys.token.p11ng.provider.CryptokiManager;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;
import org.pkcs11.jacknji11.CKM;

public class P11NgCliGenerateKeyCommand extends P11NgCliCommandBase {

    private static final Logger log = Logger.getLogger(P11NgCliGenerateKeyCommand.class);

    private static final String SLOT = "-slot";
    private static final String ALIAS = "-alias";
    private static final String LIBFILE = "-libfile";
    private static final String PIN = "-pin";
    
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
                new Parameter(PIN, "PIN for the slot", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, 
                        "The pin which is used to connect to HSM slot."));
    }
    
    @Override
    public String getMainCommand() {
        return "generatekey";
    }

    @Override
    public String getCommandDescription() {
        return "Generates key on the HSM";
    }

    @Override
    protected CommandResult execute(ParameterContainer parameters) {
        final File library = new File(parameters.get(LIBFILE));
        final String libDir = library.getParent();
        final String libName = library.getName();
        final long slotId = Long.parseLong(parameters.get(SLOT));
        final String alias = parameters.get(ALIAS);

        CryptokiDevice device = CryptokiManager.getInstance().getDevice(libName, libDir);
        CryptokiDevice.Slot slot = device.getSlot(slotId);
        slot.login(parameters.get(PIN));                  
        slot.generateKey(CKM.AES_KEY_GEN, 128, alias);
        System.out.println("Generated wrapKey" + " with alias " + alias);
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
