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

import org.apache.log4j.Logger;
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
 * Class implementing delete object command for P11Ng CLI tool.
 * 
 * @version $Id$
 *
 */
public class P11NgCliDeleteObjectCommand extends P11NgCliCommandBase {
    
    private static final Logger log = Logger.getLogger(P11NgCliDeleteObjectCommand.class);

    private static final String LIBFILE = "-libfile";
    private static final String SLOT = "-slot";
    private static final String PIN = "-pin";
    private static final String OBJECT = "-object";
    
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
                new Parameter(OBJECT, "object", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, 
                        "Object ID (decimal)"));
    }

    @Override
    public String getMainCommand() {
        return "deleteobject";
    }

    @Override
    public String getCommandDescription() {
        return "Deletes objects.";
    }

    @Override
    protected CommandResult execute(ParameterContainer parameters) {
        final long slotId = Long.parseLong(parameters.get(SLOT));
        final String objectId = parameters.get(OBJECT);
        final String lib = parameters.get(LIBFILE);
        try {
            ce = P11NgCliHelper.provideCe(lib);
            ce.Initialize();
            long session = ce.OpenSession(slotId, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
            ce.Login(session, CKU.USER, parameters.get(PIN).getBytes());
            System.out.println("Destroying object " + objectId);
            ce.DestroyObject(session, Long.parseLong(objectId));
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
