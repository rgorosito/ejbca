/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.cmpclient.commands;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.ejbca.ui.cli.infrastructure.command.CommandBase;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;

public abstract class CmpCommandBase extends CommandBase {

    public abstract PKIMessage generatePKIMessage(ParameterContainer parameters) throws Exception;
    
    public abstract CommandResult handleCMPResponse(final byte[] response, ParameterContainer parameters)  throws Exception;

    @Override
    public String getImplementationName() {
        return "CMP CLI";
    }

    @Override
    protected abstract Logger getLogger();
}
