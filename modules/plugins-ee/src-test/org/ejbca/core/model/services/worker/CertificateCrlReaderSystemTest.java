/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.model.services.worker;

import static org.junit.Assert.fail;

import java.io.File;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Properties;

import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.cert.X509CRLHolder;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCrlStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.CrlStoreSessionRemote;
import org.cesecore.certificates.crl.RevocationReasons;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenManagementProxySessionRemote;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.TraceLogMethodsRule;
import org.ejbca.core.ejb.services.ServiceSessionRemote;
import org.ejbca.core.model.services.ServiceConfiguration;
import org.ejbca.core.model.services.actions.NoAction;
import org.ejbca.core.model.services.intervals.PeriodicalInterval;
import org.ejbca.core.model.services.workers.CertificateCrlReader;
import org.ejbca.scp.publisher.ScpContainer;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.rules.TestRule;

/**
 * Unit tests for the CertificateCrlReader Worker
 * 
 * @version $Id$
 *
 */
public class CertificateCrlReaderSystemTest {

    private static final Logger log = Logger.getLogger(CertificateCrlReaderSystemTest.class);

    @Rule
    public TestRule traceLogMethodsRule = new TraceLogMethodsRule();

    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("UserPasswordExpireTest"));

    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private CertificateStoreSessionRemote certificateStoreSessionRemote = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CertificateStoreSessionRemote.class);
    private CrlStoreSessionRemote crlStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CrlStoreSessionRemote.class);
    private CryptoTokenManagementProxySessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CryptoTokenManagementProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private InternalCrlStoreSessionRemote internalCrlStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCrlStoreSessionRemote.class,
            EjbRemoteHelper.MODULE_TEST);
    private ServiceSessionRemote serviceSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ServiceSessionRemote.class);

    /** Time to wait for operations like certificate import, file deletion etc., before considering the test to have failed. Milliseconds */
    private static final long WAIT_TIME = 30_000;
    /** Sleep time in loop iterations to avoid causing too much CPU usage. Milliseconds */
    private static final long IMPORT_ITERATION_SLEEP = 500;
    private static final long DELETE_ITERATION_SLEEP = 100;

    /**
     * This test will write a certificate to a temporary file area and then use the CertificateCrlReader to import it to the system. 
     */
    @Test
    public void testReadCertificateFromDisk() throws Exception {
        log.trace(">testReadCertificateFromDisk");
        //Create an issuing CA
        final String endEntitySubjectDn = "CN=testReadCrlFromDiskUser";
        final String issuerDn = "CN=testReadCertificateFromDisk";
        X509CA testCa = CaTestUtils.createTestX509CA(issuerDn, null, false);
        caSession.addCA(admin, testCa);

        Date revDate = new Date();
        KeyPair keypair = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        final String username = "testReadCertificateFromDisk";
        EndEntityInformation user = new EndEntityInformation("username", endEntitySubjectDn, testCa.getCAId(), null, null,
                new EndEntityType(EndEntityTypes.ENDUSER), 0, 0, EndEntityConstants.TOKEN_USERGEN, 0, null);
        CertificateProfile certificateProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        int certificateProfileId = 4711;
        final CryptoToken cryptoToken = cryptoTokenManagementSession.getCryptoToken(testCa.getCAToken().getCryptoTokenId());
        Certificate usercert = testCa.generateCertificate(cryptoToken, user, keypair.getPublic(), 0, null, "10d", certificateProfile, "00000", null);
        File certificateFolder = folder.newFolder();
        //Set up reader        
        ServiceConfiguration config = getServiceConfig(CertificateCrlReader.CERTIFICATE_DIRECTORY_KEY, certificateFolder);
        final String serviceName = "testReadCertificateFromDisk";
        try {              
            ScpContainer activeCertificate = new ScpContainer()
                    .setCertificate(usercert)
                    .setIssuer(issuerDn)
                    .setUsername(username)
                    .setCertificateType(CertificateConstants.CERTTYPE_ENDENTITY)
                    .setCertificateProfile(certificateProfileId)
                    .setUpdateTime(revDate.getTime())
                    .setSerialNumber(CertTools.getSerialNumber(usercert))
                    .setRevocationDate(0)
                    .setRevocationReason(RevocationReasons.NOT_REVOKED.getDatabaseValue())
                    .setCertificateStatus(CertificateConstants.CERT_ACTIVE);
            //Write an active certificate to disk in order to simulate publishing a non-anonymous scp publishing
            File activeCertificateFile = new File(certificateFolder, "activeCertificateFile");
            FileUtils.writeByteArrayToFile(activeCertificateFile, activeCertificate.getEncoded());
            try {
                serviceSession.addService(admin, serviceName, config);
                serviceSession.activateServiceTimer(admin, serviceName);
                // Verify that the certificate gets read from disk
                if (!waitForCertificateToExist(issuerDn, usercert)) {
                    fail("Certificate was not scanned by service");
                }
                //Verify that the CRL has been removed from the folder
                if (!waitForFileDeletion(activeCertificateFile)) {
                    fail("Certificate file was not removed after being scanned.");
                }
            } finally {
                serviceSession.removeService(admin, serviceName);
            }
            //Try it again, this time just updating with the revoked status (thereby using the other publishing variant)           
            ScpContainer revokedCertificate = new ScpContainer()
                    .setIssuer(issuerDn)
                    .setSerialNumber(CertTools.getSerialNumber(usercert))
                    .setRevocationDate(0)
                    .setRevocationReason(RevocationReasons.KEYCOMPROMISE.getDatabaseValue())
                    .setCertificateStatus(CertificateConstants.CERT_REVOKED);
            File revokedCertificateFile = new File(certificateFolder, "revokedCertificateFile");
            FileUtils.writeByteArrayToFile(revokedCertificateFile, revokedCertificate.getEncoded());
            try {
                serviceSession.addService(admin, serviceName, config);
                serviceSession.activateServiceTimer(admin, serviceName);
                // Verify that the certificate gets read from disk
                if (!waitForCertificateToBeRevoked(issuerDn, usercert)) {
                    fail("Certificate was not revoked");
                }
                // Verify that the certificate gets removed from the folder
                if (!waitForFileDeletion(activeCertificateFile)) {
                    fail("Certificate file was not removed after being scanned.");
                }
            } finally {
                serviceSession.removeService(admin, serviceName);
            }
        } finally {
            CaTestUtils.removeCa(admin, testCa.getCAInfo());
            internalCertificateStoreSession.removeCertificate(usercert);
            log.trace("<testReadCertificateFromDisk");
        }
    }

    /**
     * This test will write a CRL to a temporary file area and then use the CertificateCrlReader to import it to the system. 
     */
    @Test
    public void testReadCrlFromDisk() throws Exception {
        log.trace(">testReadCrlFromDisk");
        final String endEntitySubjectDn = "CN=testReadCrlFromDiskUser";
        //Create an issuing CA
        final String issuerDn = "CN=testReadCertificateFromDisk";
        X509CA testCa = CaTestUtils.createTestX509CA(issuerDn, null, false);
        caSession.addCA(admin, testCa);
        try {
            final CryptoToken cryptoToken = cryptoTokenManagementSession.getCryptoToken(testCa.getCAToken().getCryptoTokenId());
            Date revDate = new Date();
            KeyPair keypair = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
            EndEntityInformation user = new EndEntityInformation("username", endEntitySubjectDn, testCa.getCAId(), null, null,
                    new EndEntityType(EndEntityTypes.ENDUSER), 0, 0, EndEntityConstants.TOKEN_USERGEN, 0, null);
            CertificateProfile certificateProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            Certificate usercert = testCa.generateCertificate(cryptoToken, user, keypair.getPublic(), 0, null, "10d", certificateProfile, "00000",
                    null);
            Collection<RevokedCertInfo> revcerts = new ArrayList<>();
            revcerts.add(new RevokedCertInfo(CertTools.getFingerprintAsString(usercert).getBytes(), CertTools.getSerialNumber(usercert).toByteArray(),
                    revDate.getTime(), RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD, CertTools.getNotAfter(usercert).getTime()));
            final int crlNumber = 1337;
            X509CRLHolder x509crlHolder = testCa.generateCRL(cryptoToken, CertificateConstants.NO_CRL_PARTITION, revcerts, crlNumber);
            X509CRL crl = CertTools.getCRLfromByteArray(x509crlHolder.getEncoded());
            final String serviceName = "testReadCrlFromDisk";
            File crlFolder = folder.newFolder();
            if (!crlFolder.setReadable(true, false) || !crlFolder.setWritable(true, false)) {
                log.info("Can't changes file access mode for test folder " + crlFolder.getAbsolutePath() + " (expected on Windows)");
            }
            File crlFile = new File(crlFolder, "canned.crl");
            //Write CRL to disk
            FileUtils.writeByteArrayToFile(crlFile, crl.getEncoded());
            //Set up reader        
            ServiceConfiguration config = getServiceConfig(CertificateCrlReader.CRL_DIRECTORY_KEY, crlFolder);      
            try {
                serviceSession.addService(admin, serviceName, config);
                serviceSession.activateServiceTimer(admin, serviceName);
                // Verify that the certificate gets read from disk
                if (!waitForCrlToExist(issuerDn, crlNumber)) {
                    fail("CRL was not scanned by service");
                }
                // Verify that the CRL gets removed from the folder
                if (!waitForFileDeletion(crlFile)) {
                    fail("CRL file was not removed after being scanned.");
                }
            } finally {
                serviceSession.removeService(admin, serviceName);
                internalCrlStoreSession.removeCrl(issuerDn);
            }
        } finally {
            CaTestUtils.removeCa(admin, testCa.getCAInfo());
            log.trace("<testReadCrlFromDisk");
        }
    }

    /**
     * Wait for a certificate to be imported
     * @return true if it was imported, false on timeout
     */
    private boolean waitForCertificateToExist(final String issuerDn, final Certificate usercert) throws InterruptedException {
        final long startTime = System.currentTimeMillis();
        while (System.currentTimeMillis() < startTime + WAIT_TIME) {
            final Certificate cert = certificateStoreSessionRemote.findCertificateByIssuerAndSerno(issuerDn, CertTools.getSerialNumber(usercert));
            if (cert != null) {
                if (log.isDebugEnabled()) {
                    log.debug("Certificate found after " + (System.currentTimeMillis() - startTime) + " ms");
                }
                return true; // cert has been imported now
            }
            Thread.sleep(IMPORT_ITERATION_SLEEP);
        }
        log.debug("Timed out waiting for certificate to be imported");
        return false; // timeout after 30 seconds
    }

    /**
     * Wait for a certificate to be revoked
     * @return true if it was revoked, false on timeout
     */
    private boolean waitForCertificateToBeRevoked(final String issuerDn, final Certificate usercert) throws InterruptedException {
        final long startTime = System.currentTimeMillis();
        final BigInteger serialNumber = CertTools.getSerialNumber(usercert);
        while (System.currentTimeMillis() < startTime + WAIT_TIME) {
            final Certificate cert = certificateStoreSessionRemote.findCertificateByIssuerAndSerno(issuerDn, serialNumber);
            if (cert == null) {
                fail("Certificate no longest exists?");
            }
            if (certificateStoreSessionRemote.isRevoked(issuerDn, serialNumber)) {
                if (log.isDebugEnabled()) {
                    log.debug("Certificate revoked after " + (System.currentTimeMillis() - startTime) + " ms");
                }
                return true;
            }
            Thread.sleep(IMPORT_ITERATION_SLEEP);
        }
        log.debug("Timed out waiting for certificate to be revoked");
        return false; // timeout after 30 seconds
    }

    /**
     * Wait for a CRL to be imported
     * @return true if it was imported, false on timeout
     */
    private boolean waitForCrlToExist(final String issuerDn, final int crlNumber) throws InterruptedException {
        final long startTime = System.currentTimeMillis();
        while (System.currentTimeMillis() < startTime + WAIT_TIME) {
            final byte[] crl = crlStoreSession.getCRL(issuerDn, CertificateConstants.NO_CRL_PARTITION, crlNumber);
            if (crl != null) {
                if (log.isDebugEnabled()) {
                    log.debug("CRL found after " + (System.currentTimeMillis() - startTime) + " ms");
                }
                return true; // CRL has been imported now
            }
            Thread.sleep(IMPORT_ITERATION_SLEEP);
        }
        log.debug("Timed out waiting for CRL to be imported");
        return false; // timeout after 30 seconds
    }

    /**
     * Wait for a file to be deleted.
     * @return true if it was deleted, false on timeout
     */
    private boolean waitForFileDeletion(final File file) throws InterruptedException {
        final long startTime = System.currentTimeMillis();
        while (System.currentTimeMillis() < startTime + WAIT_TIME) {
            if (!file.exists()) {
                if (log.isDebugEnabled()) {
                    log.debug("File deleted after " + (System.currentTimeMillis() - startTime) + " ms");
                }
                return true; // CRL has been imported now
            }
            Thread.sleep(DELETE_ITERATION_SLEEP);
        }
        log.debug("Timed out waiting for file to be deleted");
        return false; // timeout after 30 seconds
    }

    private ServiceConfiguration getServiceConfig(final String directoryType, final File folder) {
        ServiceConfiguration config = new ServiceConfiguration();
        config.setActive(true);
        config.setDescription("");
        // No mailsending for this Junit test service
        config.setActionClassPath(NoAction.class.getName());
        config.setActionProperties(null);
        config.setIntervalClassPath(PeriodicalInterval.class.getName());
        Properties intervalprop = new Properties();
        // Run the service every  second
        intervalprop.setProperty(PeriodicalInterval.PROP_VALUE, "3");
        intervalprop.setProperty(PeriodicalInterval.PROP_UNIT, PeriodicalInterval.UNIT_SECONDS);
        config.setIntervalProperties(intervalprop);
        config.setWorkerClassPath(CertificateCrlReader.class.getName());
        Properties workerprop = new Properties();
        workerprop.setProperty(directoryType, folder.getAbsolutePath());
        config.setWorkerProperties(workerprop);
        return config;
    }
}
