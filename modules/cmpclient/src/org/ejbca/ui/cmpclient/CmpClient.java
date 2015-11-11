/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.cmpclient;

import org.cesecore.util.CryptoProviderTools;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.library.CommandLibrary;

public class CmpClient {
    public static void main(String[] args) {
        if (args.length == 0 || !CommandLibrary.INSTANCE.doesCommandExist(args)) {
            CommandLibrary.INSTANCE.listRootCommands();
        } else {
            CryptoProviderTools.installBCProvider();
            CommandResult result = CommandLibrary.INSTANCE.findAndExecuteCommandFromParameters(args);
            if (result != CommandResult.SUCCESS) {
                System.exit(result.getReturnCode());
            }
        }
    }
}
