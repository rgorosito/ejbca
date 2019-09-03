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

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.keys.token.p11ng.provider.CryptokiDevice;
import org.cesecore.keys.token.p11ng.provider.CryptokiManager;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

public class P11NgCliDeleteKeyStoreEntryByAliasCommand extends P11NgCliCommandBase {

    private static final Logger log = Logger.getLogger(P11NgCliDeleteKeyStoreEntryByAliasCommand.class);
    
    private static final String SLOT = "-slot";
    private static final String ALIAS = "-alias";
    private static final String PIN = "-pin";
    private static final String LIBFILE = "-libfile";
    
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
                new Parameter(ALIAS, "alias", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, 
                        "Alias of the key pair on the HSM."));
    }
    
    @Override
    public String getMainCommand() {
        return "deletekeystoreentrybyalias";
    }

    @Override
    public String getCommandDescription() {
        return "Deletes keystore entry by alias.";
    }

    @Override
    protected CommandResult execute(ParameterContainer parameters) {
        final long slotId = Long.parseLong(parameters.get(SLOT));
        final String alias = parameters.get(ALIAS);
        final File library = new File(parameters.get(LIBFILE));
        final String libDir = library.getParent();
        final String libName = library.getName();
        CryptokiDevice device = CryptokiManager.getInstance().getDevice(libName, libDir);
        CryptokiDevice.Slot slot = device.getSlot(slotId);
        if (!StringUtils.isBlank(parameters.get(PIN))) {
            slot.login(parameters.get(PIN));
        }

        if (slot.removeKey(alias)) {
            System.out.println("Destroyed object with alias " + alias);
        } else {
            System.err.println("Something went wrong. All objects could not be deleted with alias " + alias);
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

}
