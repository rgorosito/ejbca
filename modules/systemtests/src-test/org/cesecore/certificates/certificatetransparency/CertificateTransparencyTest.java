/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.certificatetransparency;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.UnknownHostException;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.config.ConfigurationHolder;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.keys.util.PublicKeyWrapper;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.cesecore.certificates.certificatetransparency.CtTestData.CTLOG_PUBKEY;
import static org.cesecore.certificates.certificatetransparency.CtTestData.LABELS_A;
import static org.cesecore.certificates.certificatetransparency.CtTestData.LOG_LABEL_A;
import static org.cesecore.certificates.certificatetransparency.CtTestData.REQUEST;
import static org.cesecore.certificates.certificatetransparency.CtTestData.RESPONSE1;
import static org.easymock.EasyMock.anyString;
import static org.easymock.EasyMock.createNiceMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Test class to run certificate transparency tests
 * 
 * @version $Id$
 *
 */
public class CertificateTransparencyTest {

    private final SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
    private final CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CertificateStoreSessionRemote.class);
    private final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(EndEntityManagementSessionRemote.class);
    private final EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(EndEntityProfileSessionRemote.class); 
    private final InternalCertificateStoreSessionRemote internalCertStoreSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final CertificateProfileSessionRemote certificateProfileSessoin = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CertificateProfileSessionRemote.class);
    private GlobalConfigurationSessionRemote globalConfigSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);


    private final static Logger log = Logger.getLogger(CertificateTransparencyTest.class);

    private static SctDataCallback sctDataCallback;

    private static final int LOGSERVER_START_PORT = 8760;

    private Map<Integer, CTLogInfo> ctlogs;
    private List<CTLogTestServer> testServers;
    private ServerSocket deadServerSocket;
    private static ExecutorService threadPool;
    
    private GlobalConfiguration gcBackup;

    private final CertificateTransparency ct = new CertificateTransparencyImpl();

    // TODO: name these more uniquely
    private static final String TEST_USER_NAME = "testUserName";
    private static final String TEST_CERT_PROFILE_NAME = "testProfileName";
    private static final String TEST_EE_PROFILE_NAME = "testEEProfileName";
    
    final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(TEST_USER_NAME);

    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        
        ConfigurationHolder.backupConfiguration();
        // Set everything to the defaults to make sure the user configuration doesn't affect the test
        ConfigurationHolder.updateConfiguration("ct.cache.enabled", "true");
        ConfigurationHolder.updateConfiguration("ct.cache.maxentries", "100000");
        ConfigurationHolder.updateConfiguration("ct.cache.cleanupinterval", "10000");
        ConfigurationHolder.updateConfiguration("ct.fastfail.enabled", "true"); // not default
        ConfigurationHolder.updateConfiguration("ct.fastfail.backoff", "1000");

        // Disable certificate checks during tests
        disableCertCheck(true);
        
        // Using the same thread pool configuration as used in SctDataSessionBean
        threadPool = new ThreadPoolExecutor(8, 128, 0L, TimeUnit.MILLISECONDS, new SynchronousQueue<Runnable>());

        // Some tests are timing sensitive, so make sure everything has been loaded by the JVM
        final List<Certificate> chain = makeTestChain();
        final CertificateTransparency preloadCT = new CertificateTransparencyImpl();
        final CTLogTestServer preloadServer = new CTLogTestServer("POST", "/ct/v1/add-pre-chain",
                "application/json", REQUEST, "application/json", RESPONSE1, LOGSERVER_START_PORT+100, true, 0L);
        
        sctDataCallback = createNiceMock(SctDataCallback.class);
        expect(sctDataCallback.getThreadPool()).andReturn(threadPool).anyTimes();
        expect(sctDataCallback.findSctData(anyString())).andReturn(Collections.emptyMap()).anyTimes();
        replay(sctDataCallback);
        try {
            final byte[] pubKeyBytes = KeyTools.getBytesFromPEM(CTLOG_PUBKEY, CertTools.BEGIN_PUBLIC_KEY, CertTools.END_PUBLIC_KEY);
            final CTLogInfo ctlog = new CTLogInfo("https://127.0.0.1:" + (LOGSERVER_START_PORT + 100) + "/ct/v1/", pubKeyBytes, LOG_LABEL_A, 5000);
            final Map<Integer,CTLogInfo> logs = new LinkedHashMap<>();
            logs.put(ctlog.hashCode(), ctlog);
            fetchSCTList(preloadCT, logs, chain, 1, 1, LABELS_A, 0);
        } catch (Exception e) {
            log.warn("An exception occurred during test run to preload CT. Timing sensitive tests might fail.", e);
        } finally {
            preloadServer.close();
        }
        preloadCT.clearCaches();
    }
    
    @Before
    public void prepareTest() {
        ct.clearCaches();
        ctlogs = new LinkedHashMap<>();
        testServers = new ArrayList<>();
        gcBackup = (GlobalConfiguration) globalConfigSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
    }

    @SuppressWarnings("deprecation")
    private static void disableCertCheck(final boolean disable) {
        HttpPostTimeoutInvoker.disableCertCheck(disable);
    }
    
    @After
    public void tearDown() throws Exception {
        globalConfigSession.saveConfiguration(admin, gcBackup);
    }
    
    @Test
    public void testPreCertStoredIfCannotConnectToLogServer() throws Exception {
        log.trace(">testPreCertStoredIfCannotConnectToLogServer");

        final KeyPair keyPair = KeyTools.genKeys("2048", AlgorithmConstants.KEYALGORITHM_RSA);

        final CAInfo caInfo = CaTestUtils.getClientCertCaInfo(admin);
        X509Certificate storedCertificate = null;

        try {
            GlobalConfiguration globalConfiguration = (GlobalConfiguration) globalConfigSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
            final byte[] eccKey = KeyTools.getBytesFromPEM(CTLOG_PUBKEY, CertTools.BEGIN_PUBLIC_KEY, CertTools.END_PUBLIC_KEY);

            // CT log accepting certificates expiring in 2016
            final CTLogInfo ctLog1 = new CTLogInfo(String.format("http://127.0.0.1:%d/ct/v1/", LOGSERVER_START_PORT + 0), eccKey, LOG_LABEL_A, 1500);
            ctLog1.setExpirationYearRequired(2016);
            ctlogs.put(ctLog1.getLogId(), ctLog1);
            
            globalConfiguration.setCTLogs((LinkedHashMap<Integer, CTLogInfo>) ctlogs);
            
            globalConfigSession.saveConfiguration(admin, globalConfiguration);
            
            final CertificateProfile certProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);

            certProfile.setCtMinScts(1);
            certProfile.setCtMaxScts(1);
            certProfile.setNumberOfSctByCustom(true);
            certProfile.setMaxNumberOfSctByCustom(true);
            certProfile.setEnabledCtLabels(new LinkedHashSet<>(Arrays.asList(LOG_LABEL_A)));

            certProfile.setUseCertificateTransparencyInCerts(true);
            
            final int certProfileId = certificateProfileSessoin.addCertificateProfile(admin, TEST_CERT_PROFILE_NAME, certProfile);
            
            final EndEntityProfile endEntityProfile = new EndEntityProfile(true);
            endEntityProfile.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, Integer.toString(certProfileId));
            endEntityProfile.setValue(EndEntityProfile.DEFAULTCERTPROFILE, 0, Integer.toString(certProfileId));
            endEntityProfile.setValue(EndEntityProfile.AVAILCAS, 0, Integer.toString(SecConst.ALLCAS));
            endEntityProfile.setValue(EndEntityProfile.DEFAULTCA, 0, Integer.toString(SecConst.ALLCAS));
            
            final int endEntityProfileId = endEntityProfileSession.addEndEntityProfile(admin, TEST_EE_PROFILE_NAME, endEntityProfile);
            
            final EndEntityInformation user = new EndEntityInformation(TEST_USER_NAME, "CN=" + TEST_USER_NAME + ",O=CertProfileTest", caInfo.getCAId(),
                    null, null, EndEntityTypes.ENDUSER.toEndEntityType(), endEntityProfileId, certProfileId,
                    EndEntityConstants.TOKEN_USERGEN, null);
            user.setPassword("foo123");
            endEntityManagementSession.addUser(admin, user, false);

            try {
                signSession.createCertificate(admin, TEST_USER_NAME, "foo123", new PublicKeyWrapper(keyPair.getPublic()));
                fail("Should throw");
            } catch (CertificateCreateException e) {
                // Make sure we fail for the right reason
                if (e.getCause() instanceof CTLogException) {
                    assertTrue("Wrong error message. Was: " + e.getCause().getMessage(),
                            e.getCause().getMessage().contains("Insufficient SCTs, minimum is 1, but got 0."));
                }
            }
            storedCertificate = certificateStoreSession
                    .findLatestX509CertificateBySubject("CN=" + TEST_USER_NAME + ",O=CertProfileTest");

            assertNotNull("Certificate for the data was null!", storedCertificate);
            assertNotNull("Poison field for the certificate was null!",
                    (storedCertificate.getExtensionValue(CertTools.PRECERT_POISON_EXTENSION_OID)));

        } finally {
            // Clean up database
            endEntityManagementSession.revokeAndDeleteUser(admin, TEST_USER_NAME, ReasonFlags.unused);
            endEntityProfileSession.removeEndEntityProfile(admin, TEST_EE_PROFILE_NAME);
            certificateProfileSessoin.removeCertificateProfile(admin, TEST_CERT_PROFILE_NAME);
            internalCertStoreSession.removeCertificate(storedCertificate);
        }
        log.trace("<testPreCertStoredIfCannotConnectToLogServer");
    }

    static List<Certificate> makeTestChain() {
        final List<Certificate> chain = new ArrayList<>();
        chain.add(pemToCert(CtTestData.TESTCERT_PRECERTIFICATE));
        chain.add(pemToCert(CtTestData.ISSUER_CERT));
        return chain;
    }

    static Certificate pemToCert(final String pem) {
        try {
            final byte[] bytes = KeyTools.getBytesFromPEM(pem, CertTools.BEGIN_CERTIFICATE, CertTools.END_CERTIFICATE);
            return CertTools.getCertfromByteArray(bytes, Certificate.class);
        } catch (CertificateException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private static byte[] fetchSCTList(final CertificateTransparency ct, final Map<Integer, CTLogInfo> ctlogs, final List<Certificate> chain,
            final int minSCTs, final int maxSCTs, final LinkedHashSet<String> labels, final int maxRetries) throws CTLogException {
        final CertificateProfile certProfile = new CertificateProfile();
        certProfile.setUseCertificateTransparencyInCerts(true);
        certProfile.setEnabledCtLabels(labels);
        certProfile.setNumberOfSctByCustom(true);
        certProfile.setNumberOfSctByValidity(false);
        certProfile.setCtMinScts(minSCTs);
        certProfile.setCtMaxScts(maxSCTs);
        certProfile.setCTMaxRetries(maxRetries);
        final CTSubmissionConfigParams config = new CTSubmissionConfigParams();
        config.setConfiguredCTLogs(ctlogs);
        config.setValidityPolicy(new GoogleCtPolicy());
        return ct.fetchSCTList(chain, certProfile, config, sctDataCallback);
    }

    private void addLog(final int port, final boolean tls, final String logKeyPEM, final String label) {
        final byte[] pubKeyBytes = KeyTools.getBytesFromPEM(logKeyPEM, CertTools.BEGIN_PUBLIC_KEY, CertTools.END_PUBLIC_KEY);
        final String protocol = (tls ? "https" : "http");
        final CTLogInfo ctlog = new CTLogInfo(protocol + "://127.0.0.1:" + port + "/ct/v1/", pubKeyBytes, null, 1500);
        ctlog.setLabel(label);
        ctlogs.put(ctlog.hashCode(), ctlog);
    }
    
    public void createTestCTLogServer(final int port, final String logKeyPEM, final String requestContent, final String responseContent) throws UnknownHostException, IOException {
        addLog(port, false, logKeyPEM, LOG_LABEL_A);
        testServers.add(new CTLogTestServer("POST", "/ct/v1/add-pre-chain",
            "application/json", requestContent, "application/json", responseContent, port, false, 0L));
    }
    
    public void createDeadServerWithLabel(final int port, final String logKeyPEM, final String label) throws IOException {
        addLog(port, false, logKeyPEM, label);
        deadServerSocket = new ServerSocket();
        deadServerSocket.setReuseAddress(true);
        deadServerSocket.bind(new InetSocketAddress("127.0.0.1", port));
    }

}
