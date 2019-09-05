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

import static org.cesecore.keys.token.p11ng.TokenEntry.TYPE_PRIVATEKEY_ENTRY;
import static org.cesecore.keys.token.p11ng.TokenEntry.TYPE_SECRETKEY_ENTRY;

import java.io.File;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.List;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.p11ng.provider.CryptokiDevice;
import org.cesecore.keys.token.p11ng.provider.CryptokiManager;
import org.cesecore.keys.token.p11ng.provider.SlotEntry;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Class implementing the list keystore entries command for P11Ng CLI tool.
 * 
 * @version $Id$
 *
 */
public class P11NgCliListKeystoreEntriesCommand extends P11NgCliCommandBase {

    private static final Logger log = Logger.getLogger(P11NgCliListKeystoreEntriesCommand.class);
    
    private static final String LIBFILE = "-libfile";
    private static final String SLOT = "-slot";

    //Register all parameters
    {
        registerParameter(
                new Parameter(LIBFILE, "lib file", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, "Shared library path"));
        registerParameter(new Parameter(SLOT, "HSM slot", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "Slot on the HSM which will be used."));
    }
    
    @Override
    public String getMainCommand() {
        return "listkeystoreentries";
    }

    @Override
    public String getCommandDescription() {
        return "Lists keystore entries on the slot.";
    }

    @Override
    protected CommandResult execute(ParameterContainer parameters) {
        final File library = new File(parameters.get(LIBFILE));
        final String libDir = library.getParent();
        final String libName = library.getName();
        Security.addProvider(new BouncyCastleProvider());
        CryptokiDevice device = CryptokiManager.getInstance().getDevice(libName, libDir);
        
        final long slotId = Long.parseLong(parameters.get(SLOT));
        CryptokiDevice.Slot slot = device.getSlot(slotId);
        
        Enumeration<SlotEntry> e = null;
        try {
            e = slot.aliases();
        } catch (CryptoTokenOfflineException e1) {
            log.error("Error happened while reading aliases from the slot!", e1);
        }
        final StringBuilder buff = new StringBuilder();
        while (e.hasMoreElements()) {
            final SlotEntry slotEntry  = e.nextElement();                
            final String keyAlias = slotEntry.getAlias();
            final String type;
            if (slotEntry.getType().equals(TYPE_PRIVATEKEY_ENTRY)) {
                type = TYPE_PRIVATEKEY_ENTRY;
            } else if (slotEntry.getType().equals(TYPE_SECRETKEY_ENTRY)) {
                type = TYPE_SECRETKEY_ENTRY;
            } else {
                type = null;
            }
            
            buff.append("Entry ").append(type).append(" \"").append(keyAlias).append("\"");
            List<Certificate> certificateChain = slot.getCertificateChain(keyAlias);
            for (Certificate cert : certificateChain) {
                buff.append(", ");
                buff.append("0x");
                buff.append(((X509Certificate) cert).getSerialNumber().toString(16));
            }
            buff.append("\n");
        }
        System.out.println(buff.toString());
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
