/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.p11ngcli.helper;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

import org.apache.log4j.Logger;
import org.cesecore.keys.token.p11ng.provider.CryptokiDevice;
import org.ejbca.ui.p11ngcli.command.P11NgCliListSlotsCommand;
import org.pkcs11.jacknji11.CEi;
import org.pkcs11.jacknji11.CKA;
import org.pkcs11.jacknji11.Ci;
import org.pkcs11.jacknji11.jna.JNAi;
import org.pkcs11.jacknji11.jna.JNAiNative;

import com.sun.jna.Native;
import com.sun.jna.NativeLibrary;

/**
 * Helper class keeping stuff used by P11Ng CLI command classes
 *
 * @version $Id$
 *
 */
public final class P11NgCliHelper {
    
    private static final Logger log = Logger.getLogger(P11NgCliListSlotsCommand.class);
    
    private static final int KEY_AUTHORIZATION_INIT_SIGN_SALT_SIZE = 32;
    public static final int HASH_SIZE = 32;
    public static final int KAK_SIZE = 2048;

    
    // used by the testSign stresstest command
    public static long startTime;

    
    public static CEi provideCe(final String lib) {
        final File library = new File(lib);
        final String libDir = library.getParent();
        final String libName = library.getName();
        log.debug("Adding search path: " + libDir);
        NativeLibrary.addSearchPath(libName, libDir);
        JNAiNative jnaiNative = (JNAiNative) Native.loadLibrary(libName, JNAiNative.class);
        return new CEi(new Ci(new JNAi(jnaiNative)));
    }
    
    public static void shutdown(final OperationsThread[] threads, final int warmupTime) {
        for (final OperationsThread thread : threads) {
            thread.stopIt();
        }

        int totalOperationsPerformed = 0;

        // wait until all stopped
        try {
            for (int i = 0; i < threads.length; i++) {
                final OperationsThread thread = threads[i];
                thread.join();
                final int numberOfOperations = thread.getNumberOfOperations();
                log.info("Number of operations for thread " + i + ": " + numberOfOperations);
                totalOperationsPerformed += thread.getNumberOfOperations();
            }
        } catch (InterruptedException ex) {
            log.error("Interrupted: " + ex.getMessage());
        }

        long totalRunTime = System.currentTimeMillis() - startTime - warmupTime;
        final double tps;
        if (totalRunTime > 1000) {
            tps = totalOperationsPerformed / (totalRunTime / 1000d);
        } else {
            tps = Double.NaN;
        }

        log.info("Total number of signings: " + totalOperationsPerformed);
        log.info("Signings per second: " + tps);
    }
    
    public static byte[] signHashPss(byte[] hash, long hashLen, int length, Key privateKey) 
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException {
        // Due to requirements at the HSM side we have to use RAW signer
        Signature signature = Signature.getInstance("RawRSASSA-PSS", "BC");
        PSSParameterSpec pssParameterSpec = new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, KEY_AUTHORIZATION_INIT_SIGN_SALT_SIZE, 
                PSSParameterSpec.DEFAULT.getTrailerField());
        signature.setParameter(pssParameterSpec);
        signature.initSign((PrivateKey) privateKey, new SecureRandom());
        signature.update(hash);
        byte[] signBytes = signature.sign();
        return signBytes;
    }
    
    public static long[] getPrivateKeyFromHSM(CryptokiDevice.Slot slot, final String alias) {
        // Get the private key from HSM
        long[] privateKeyObjects = slot.findPrivateKeyObjectsByID(slot.aquireSession(), new CKA(CKA.ID, alias.getBytes(StandardCharsets.UTF_8)).getValue());
        if (privateKeyObjects.length == 0) {
            throw new IllegalStateException("No private key found for alias '" + alias + "'");
        }
        if (log.isDebugEnabled()) {
            log.debug("Private key  with Id: '" + privateKeyObjects[0] + "' found for key alias '" + alias + "'");
        }
        return privateKeyObjects;
    }
    
    public static synchronized void cleanUp(final CEi ce, final long session) {
        ce.Logout(session);
        ce.CloseSession(session);
        ce.Finalize();
    }
    
    public static int bitsToBytes(final int kakSize) {
        int result = (((kakSize) + 7)/8);
        return result;
    }
    
}
