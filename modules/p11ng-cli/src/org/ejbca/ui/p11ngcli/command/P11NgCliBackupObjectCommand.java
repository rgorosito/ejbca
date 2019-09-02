package org.ejbca.ui.p11ngcli.command;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

import org.apache.log4j.Logger;
import org.cesecore.keys.token.p11ng.PToPBackupObj;
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

import com.sun.jna.ptr.LongByReference;

public class P11NgCliBackupObjectCommand extends P11NgCliCommandBase {
    
    private static final Logger log = Logger.getLogger(P11NgCliBackupObjectCommand.class);

    private static final String LIBFILE = "-libfile";
    private static final String SLOT = "-slot";
    private static final String USER_AND_PIN = "-user_and_pin";
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
                new Parameter(OBJECT_SPEC_ID, "object spec id", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, 
                        "idx of the key to back up"));        
        registerParameter(
                new Parameter(BACKUPFILE, "backup file", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, 
                        "full path to the file where backup bytes would be stored"));  
    }
    
    @Override
    public String getMainCommand() {
        return "backupobject";
    }

    @Override
    public String getCommandDescription() {
        return "Backs up a key from the HSM on the backup file. CP5 specific operation.";
    }

    @Override
    protected CommandResult execute(ParameterContainer parameters) {
        final long slotId = Long.parseLong(parameters.get(SLOT));
        final File library = new File(parameters.get(LIBFILE));
        final String libDir = library.getParent();
        final String libName = library.getName();
        CryptokiDevice device = CryptokiManager.getInstance().getDevice(libName, libDir);
        device.getSlot(slotId);                    
        
        ce = P11NgCliHelper.provideCe(parameters.get(LIBFILE));
        long session = ce.OpenSession(slotId, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
        ce.Login(session, CKU.CKU_CS_GENERIC, parameters.get(USER_AND_PIN).getBytes(StandardCharsets.UTF_8));
        long objectHandle = Long.parseLong(parameters.get(OBJECT_SPEC_ID));
        
        PToPBackupObj ppBackupObj = new PToPBackupObj(null);
        LongByReference backupObjectLength = new LongByReference();
        
        ce.backupObject(session, objectHandle, ppBackupObj.getPointer(), backupObjectLength);
        
        int length = (int) backupObjectLength.getValue();
        byte[] resultBytes = ppBackupObj.getValue().getByteArray(0, length);
        final String backupFile = parameters.get(BACKUPFILE);
        
        write2File(resultBytes, backupFile);
        P11NgCliHelper.cleanUp(ce, session);
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
    
    private void write2File(byte[] bytes, String filePath) {
        try (OutputStream os = new FileOutputStream(new File(filePath))) {
            os.write(bytes);
        } catch (Exception e) {
            log.error("Error happened while writing key to file!", e);
        }
    }

}
