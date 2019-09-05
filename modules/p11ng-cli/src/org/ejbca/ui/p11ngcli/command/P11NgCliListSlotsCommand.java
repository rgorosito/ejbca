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

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.apache.log4j.Logger;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;
import org.ejbca.ui.p11ngcli.helper.P11NgCliHelper;
import org.pkcs11.jacknji11.CEi;
import org.pkcs11.jacknji11.CK_TOKEN_INFO;

/**
 * Class implementing the list slots entries command for P11Ng CLI tool.
 * 
 * @version $Id$
 *
 */
public class P11NgCliListSlotsCommand extends P11NgCliCommandBase {
    
    private static final Logger log = Logger.getLogger(P11NgCliListSlotsCommand.class);
    
    private static final String LIBFILE = "-libfile";
    private static CEi ce;
    
    //Register all parameters
    {
        registerParameter(
                new Parameter(LIBFILE, "lib file", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, 
                        "Shared library path"));
    }

    @Override
    public String getMainCommand() {
        return "listslots";
    }

    @Override
    public String getCommandDescription() {
        return "Lists slots available on the HSM";
    }

    @Override
    protected CommandResult execute(ParameterContainer parameters) {
        log.trace(">executeCommand");
        final String lib = parameters.get(LIBFILE);
        try {
            ce = P11NgCliHelper.provideCe(lib);
            ce.Initialize();
            long[] allSlots = ce.GetSlotList(false);
            System.out.println("All slots:        " + Arrays.toString(allSlots));
            long[] slots = ce.GetSlotList(true);
            System.out.println("Slots with token: " + Arrays.toString(slots));
            
            for (long slot : allSlots) {
                CK_TOKEN_INFO info = ce.GetTokenInfo(slot);
                System.out.println("ID: " + slot + ", Label: " + new String(info.label, StandardCharsets.UTF_8));
            }
        } finally {
            ce.Finalize();
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
