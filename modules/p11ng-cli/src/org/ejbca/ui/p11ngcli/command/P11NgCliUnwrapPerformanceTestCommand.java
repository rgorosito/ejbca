package org.ejbca.ui.p11ngcli.command;

import java.io.File;

import org.apache.log4j.Logger;
import org.cesecore.keys.token.p11ng.provider.CryptokiDevice;
import org.cesecore.keys.token.p11ng.provider.CryptokiManager;
import org.cesecore.keys.token.p11ng.provider.GeneratedKeyData;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;
import org.ejbca.ui.p11ngcli.helper.FailureCallback;
import org.ejbca.ui.p11ngcli.helper.OperationsThread;
import org.ejbca.ui.p11ngcli.helper.P11NgCliHelper;
import org.ejbca.ui.p11ngcli.helper.UnwrapThread;
import org.pkcs11.jacknji11.CKM;

public class P11NgCliUnwrapPerformanceTestCommand extends P11NgCliCommandBase {
    
    private static final Logger log = Logger.getLogger(P11NgCliUnwrapPerformanceTestCommand.class);
    
    private static final String SLOT = "-slot";
    private static final String PIN = "-pin";
    private static final String WRAPKEY = "-wrapkey";
    private static final String SIGNATUREALGORITHM = "-signaturealgorithm";
    private static final String THREADS = "-threads";
    private static final String WARMUPTIME = "-warmuptime";
    private static final String TIMELIMIT = "-timelimit";
    private static final String USE_CACHE = "-use_cache";
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
                new Parameter(USE_CACHE, "use cache", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, 
                        "For sign-/unwrapPerformanceTest: Whether key objects are fetched from cache instead of HSM token (default: true)"));
        registerParameter(
                new Parameter(SIGNATUREALGORITHM, "signature algorithm", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, 
                        "For sign-/unwrapPerformanceTest: Signature algorithm to use (default: SHA256withRSA)"));
        registerParameter(
                new Parameter(THREADS, "threads", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, 
                        "For sign-/unwrapPerformanceTest: Number of stresstest threads to run (default: 1)"));
        registerParameter(
                new Parameter(WARMUPTIME, "warm up time", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, 
                        "For sign-/unwrapPerformanceTest: Don't count number of signings and response times until after this time (in milliseconds). Default=0 (no warmup time)."));
        registerParameter(
                new Parameter(TIMELIMIT, "time limit", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, 
                        "For sign-/unwrapPerformanceTest: Optional. Only run for the specified time (in milliseconds)."));
        registerParameter(
                new Parameter(WRAPKEY, "wrap key", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, 
                        "Label of key to wrap with"));
    }
    
    



    @Override
    public String getMainCommand() {
        return "unwrapperformancetest";
    }

    @Override
    public String getCommandDescription() {
        return "Runs a unwrapping performance test.";
    }

    @Override
    protected CommandResult execute(ParameterContainer parameters) {
        final long slotId = Long.parseLong(parameters.get(SLOT));
        final String pin = parameters.get(PIN);
        final String wrapkey = parameters.get(WRAPKEY);
        
        String signatureAlgorithm = parameters.get(SIGNATUREALGORITHM);
        if (signatureAlgorithm == null) {
            signatureAlgorithm = "SHA256withRSA";
        }
        
        final String threadsString = parameters.get(THREADS);
        int numThreads = 0;
        int warmupTime = 0;
        int timeLimit = 0;
        
        try {
            numThreads = Integer.parseInt(threadsString);
        } catch (NumberFormatException e) {
            log.info("Illegal number of threads: " + threadsString);
        }
        
        if (numThreads < 1) {
            log.info("Illegal number of threads: " + threadsString);
        }
        
        final String warmupTimeString = parameters.get(WARMUPTIME);
        try {
            warmupTime = Integer.parseInt(warmupTimeString);
        } catch (NumberFormatException e) {
            log.info("Illegal warmup time: " + warmupTimeString);
        }
        
        if (warmupTime < 0) {
            log.info("Warmup time can not be negative");
        }
        
        final String timeLimitString = parameters.get(TIMELIMIT);
        
        if (timeLimitString != null) {
            try {
                timeLimit = Integer.parseInt(timeLimitString);
                
                if (timeLimit < 0) {
                    log.error("Time limit can not be negative");
                }
            } catch (NumberFormatException ex) {
                log.error("Illegal time limit: " + timeLimitString);
            }
        } else {
            timeLimit = -1;
        }
        
        boolean useCache = Boolean.parseBoolean(parameters.get(USE_CACHE));
        
        try {
            final File library = new File(parameters.get(LIBFILE));
            final String libDir = library.getParent();
            final String libName = library.getName();
            runUnwrapPerformanceTest(wrapkey, libName, libDir, slotId, pin,
                                     numThreads, warmupTime, timeLimit, 
                                     signatureAlgorithm, useCache);
        } catch (Exception ex) {
            log.error("Failed to start: " + ex.getMessage());
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        return CommandResult.SUCCESS;
    }

    @Override
    public String getFullHelpText() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    protected Logger getLogger() {
        return log;
    }
    
    private void runUnwrapPerformanceTest(final String alias, final String libName, final String libDir, final long slotId, final String pin,
            final int numberOfThreads, final int warmupTime, final int timeLimit, final String signatureAlgorithm, final boolean useCache) throws InterruptedException
            {
        final UnwrapThread[] threads = new UnwrapThread[numberOfThreads];

        Thread shutdownHook = new Thread() {
            @Override
            public void run() {
                if (log.isDebugEnabled()) {
                    log.debug("Shutdown hook called");
                }
                P11NgCliHelper.shutdown(threads, warmupTime);
            }
        };

        Runtime.getRuntime().addShutdownHook(shutdownHook);

        final FailureCallback failureCallback = new FailureCallback() {

            @Override
            public void failed(OperationsThread thread, String message) throws Exception {
                for (final OperationsThread w : threads) {
                    w.stopIt();
                }

                // Print message
                log.error("   " + message);
                throw new Exception(message);
            }
        };

        final CryptokiDevice device = CryptokiManager.getInstance().getDevice(libName, libDir);
        final CryptokiDevice.Slot slot = device.getSlot(slotId);
        slot.login(pin);
        final long wrappingCipherAlgo = CKM.AES_CBC_PAD;
        final GeneratedKeyData wrappedKey = slot.generateWrappedKey(alias, "RSA", "2048", wrappingCipherAlgo);

        for (int i = 0; i < numberOfThreads; i++) {
            threads[i] = new UnwrapThread(i, failureCallback, alias, libName, libDir, slotId, pin, warmupTime, timeLimit, signatureAlgorithm,
                    wrappedKey, wrappingCipherAlgo, useCache);
        }

        // wait 1 sec to start
        Thread.sleep(1000);

        P11NgCliHelper.startTime = System.currentTimeMillis();

        for (int i = 0; i < numberOfThreads; i++) {
            if (log.isDebugEnabled()) {
                log.debug("thread: " + i);
            }
            threads[i].start();
        }

        // Wait for the threads to finish
        try {
            for (final UnwrapThread w : threads) {
                if (log.isDebugEnabled()) {
                    log.debug("Waiting for thread " + w.getName());
                }
                w.join();
                if (log.isDebugEnabled()) {
                    log.debug("Thread " + w.getName() + " stopped");
                }
            }
        } catch (InterruptedException ex) {
            if (log.isDebugEnabled()) {
                log.debug("Interupted when waiting for thread: " + ex.getMessage());
            }
        }
    }

}
