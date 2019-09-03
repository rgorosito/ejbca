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
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;

import org.apache.log4j.Logger;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.keys.token.p11ng.provider.CryptokiDevice;
import org.cesecore.keys.token.p11ng.provider.CryptokiManager;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Class implementing generate key pair command for P11Ng CLI tool
 * 
 * @version $Id$
 *
 */
public class P11NgCliGenerateKeyPairCommand extends P11NgCliCommandBase {
    
    private static final Logger log = Logger.getLogger(P11NgCliGenerateKeyPairCommand.class);

    private static final String LIBFILE = "-libfile";
    private static final String SLOT = "-slot";
    private static final String ALIAS = "-alias";
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
        return "generatekeypair";
    }

    @Override
    public String getCommandDescription() {
        return "Generates a key pair";
    }

    @Override
    protected CommandResult execute(ParameterContainer parameters) {
        final long slotId = Long.parseLong(parameters.get(SLOT));
        final String alias = parameters.get(ALIAS);
        final File library = new File(parameters.get(LIBFILE));
        final String libDir = library.getParent();
        final String libName = library.getName();
        
        CryptokiDevice device = CryptokiManager.getInstance().getDevice(libName, libDir);
        final CryptokiDevice.Slot slot = device.getSlot(slotId);
        slot.login(parameters.get(PIN));       
        
        final Map<Long, Object> publicAttributesMap = new HashMap<>();
        final Map<Long, Object> privateAttributesMap = new HashMap<>();

        try {
            slot.generateRsaKeyPair("RSA", alias, false, publicAttributesMap, privateAttributesMap, null, true);
        } catch (CertificateException | OperatorCreationException ex) {
            log.error("Key generation failed! ", ex);
            System.err.println("Key generation failed! " + ex.getMessage()); 
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        System.out.println("Generated key pair with alias " + alias);
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
