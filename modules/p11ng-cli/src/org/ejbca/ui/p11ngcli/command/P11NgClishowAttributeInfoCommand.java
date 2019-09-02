package org.ejbca.ui.p11ngcli.command;

import java.nio.charset.StandardCharsets;

import org.apache.log4j.Logger;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;
import org.ejbca.ui.p11ngcli.helper.P11NgCliHelper;
import org.pkcs11.jacknji11.CEi;
import org.pkcs11.jacknji11.CKA;
import org.pkcs11.jacknji11.CKO;
import org.pkcs11.jacknji11.CKU;
import org.pkcs11.jacknji11.CK_SESSION_INFO;

public class P11NgClishowAttributeInfoCommand extends P11NgCliCommandBase {

    private static final Logger log = Logger.getLogger(P11NgCliShowTokenInfoCommand.class);

    private static final String LIBFILE = "-libfile";
    private static final String SLOT = "-slot";
    private static final String USER_AND_PIN = "-user_and_pin";
    private static final String ALIAS = "-alias";

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
                new Parameter(ALIAS, "alias", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, 
                        "Alias of the key pair on the HSM."));
    }
    
    @Override
    public String getMainCommand() {
        return "showattributeinfo";
    }

    @Override
    public String getCommandDescription() {
        return "Prints information about attribute.";
    }

    @Override
    protected CommandResult execute(ParameterContainer parameters) {
        final String lib = parameters.get(LIBFILE);
        try {
            ce = P11NgCliHelper.provideCe(lib);
            final long slotId = Long.parseLong(parameters.get(SLOT));
            long session = ce.OpenSession(slotId, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
            ce.Login(session, CKU.CKU_CS_GENERIC, parameters.get(USER_AND_PIN).getBytes(StandardCharsets.UTF_8));
            long[] privateObjects = ce.FindObjects(session, new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, CKO.PRIVATE_KEY), new CKA(CKA.LABEL, parameters.get(ALIAS)));
            System.out.println("Size of the privateObjects array is " + privateObjects.length);
            for (long object : privateObjects) {
                System.out.println("The key label is : " + ce.GetAttributeValue(session, object, CKA.VENDOR_PTK_USAGE_COUNT).getValueStr());
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
