package org.ejbca.ui.p11ngcli.command;

import java.io.File;
import java.util.HashMap;
import java.util.Map;

import org.apache.log4j.Logger;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;
import org.ejbca.ui.p11ngcli.helper.FailureCallback;
import org.ejbca.ui.p11ngcli.helper.OneTimeThread;
import org.ejbca.ui.p11ngcli.helper.OperationsThread;
import org.ejbca.ui.p11ngcli.helper.P11NgCliHelper;

public class P11NgCliOneTimePerformanceTestCommand extends P11NgCliCommandBase {

    private static final Logger log = Logger.getLogger(P11NgCliOneTimePerformanceTestCommand.class);
    
    private static final String SLOT = "-slot";
    private static final String LIBFILE = "-libfile";
    private static final String PIN = "-pin";
    private static final String USE_CACHE = "-use_cache";
    private static final String SIGNATUREALGORITHM = "-signaturealgorithm";
    private static final String THREADS = "-threads";
    private static final String WARMUPTIME = "-warmuptime";
    private static final String TIMELIMIT = "-timelimit";

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
    }
    
    
    // used by the testSign stresstest command
    private long startTime;
    
    @Override
    public String getMainCommand() {
        return "onetimeperformancetest";
    }

    @Override
    public String getCommandDescription() {
        return "Runs a one time performance test.";
    }

    @Override
    protected CommandResult execute(ParameterContainer parameters) {
        final long slotId = Long.parseLong(parameters.get(SLOT));
        final String pin = parameters.get(PIN);                

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
            log.error("Illegal number of threads: " + threadsString, e);
        }
        
        if (numThreads < 1) {
            log.error("Illegal number of threads: " + threadsString);
        }
        
        final String warmupTimeString = parameters.get(WARMUPTIME);
        try {
            warmupTime = Integer.parseInt(warmupTimeString);
        } catch (NumberFormatException e) {
            log.error("Illegal warmup time: " + warmupTimeString);
        }
        
        if (warmupTime < 0) {
            log.info("Warmup time can not be negative");
        }
        
        final String timeLimitString = parameters.get(TIMELIMIT);
        
        if (timeLimitString != null) {
            try {
                timeLimit = Integer.parseInt(timeLimitString);
                
                if (timeLimit < 0) {
                    log.info("Time limit can not be negative");
                }
            } catch (NumberFormatException ex) {
                log.info("Illegal time limit: " + timeLimitString);
            }
        } else {
            timeLimit = -1;
        }

        boolean useCache = Boolean.parseBoolean(parameters.get(USE_CACHE));
        
        // For simplicity we skip overriding the default attributes.
        Map<Long, Object> publicAttributesMap = new HashMap<>();
        Map<Long, Object> privateAttributesMap = new HashMap<>();

        try {
            final File library = new File(parameters.get(LIBFILE));
            final String libDir = library.getParent();
            final String libName = library.getName();
            oneTimePerformanceTest(libName, libDir, slotId, pin,
                           numThreads, warmupTime, timeLimit, useCache, signatureAlgorithm, publicAttributesMap, privateAttributesMap);
        } catch (InterruptedException ex) {
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
        // TODO Auto-generated method stub
        return null;
    }
    
    private void oneTimePerformanceTest(final String libName, final String libDir, final long slotId, final String pin, final int numberOfThreads,
            final int warmupTime, final int timeLimit, final boolean useCache, final String signatureAlgorithm, Map<Long, Object> publicAttributesMap,
            Map<Long, Object> privateAttributesMap) throws InterruptedException {
        final OneTimeThread[] threads = new OneTimeThread[numberOfThreads];

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
            public void failed(OperationsThread thread, String message) {
                for (final OperationsThread w : threads) {
                    w.stopIt();
                }
                // Print message
                log.error("   " + message);
            }
        };

        for (int i = 0; i < numberOfThreads; i++) {
            threads[i] = new OneTimeThread(i, failureCallback, libName, libDir, slotId, pin, warmupTime, timeLimit, useCache, signatureAlgorithm,
                    publicAttributesMap, privateAttributesMap);
        }

        // wait 1 sec to start
        Thread.sleep(1000);

        startTime = System.currentTimeMillis();

        for (int i = 0; i < numberOfThreads; i++) {
            if (log.isDebugEnabled()) {
                log.debug("thread: " + i);
            }
            threads[i].start();
        }

        // Wait for the threads to finish
        try {
            for (final OneTimeThread w : threads) {
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
