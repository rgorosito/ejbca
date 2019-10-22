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

import java.net.ServerSocket;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.cert.X509Extension;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.CertificateWrapper;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.keys.util.PublicKeyWrapper;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.junit.Test;

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
    
    private static final SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
    private static final CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);

    private final static Logger log = Logger.getLogger(CertificateTransparencyTest.class);

    private static SctDataCallback sctDataCallback;
    
    private static final int LOGSERVER_START_PORT = 8760;
    
    private Map<Integer,CTLogInfo> ctlogs;
    private ServerSocket deadServerSocket;

    private final CertificateTransparency ct = new CertificateTransparencyImpl();

    private static final String TEST_USER_NAME = "testUserName";
    
    final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(TEST_USER_NAME);
    
    @Test
    public void testPreCertStoredIfCannotConnectToLogServer() throws Exception {
        log.trace(">testPreCertStoredIfCannotConnectToLogServer");
        
        final KeyPair keyPair = KeyTools.genKeys("2048", AlgorithmConstants.KEYALGORITHM_RSA);
        CTLogTest.createTestCTLogServer(LOGSERVER_START_PORT, CtTestData.CTLOG_PUBKEY, CtTestData.REQUEST, CtTestData.RESPONSE1);
        
        CTLogTest.createDeadServerWithLabel(LOGSERVER_START_PORT + 3, CtTestData.CTLOG_PUBKEY, CtTestData.LOG_LABEL_A);
        
        final X509Certificate clientCertificate = (X509Certificate) signSession.createCertificate(admin, TEST_USER_NAME, "foo123", new PublicKeyWrapper(keyPair.getPublic()));
        final List<Certificate> certificateChain = new ArrayList<>();
        certificateChain.add(clientCertificate);
        
        try {
            fetchSCTList(makeTestChain(), 1, 1, CtTestData.LABELS_A, 0);
            fail("Should throw");
        } catch (CTLogException e) {
            // Make sure we fail for the right reason
            assertTrue("Wrong error message. Was: " + e.getMessage(), e.getMessage().contains("Insufficient SCTs, minimum is 1, but got 0."));
        }
        
        final String fingerprint = CertTools.getFingerprintAsString(clientCertificate);
        CertificateWrapper certWrapper = certificateStoreSession.findCertificateByFingerprintRemote(fingerprint);
 
        assertNotNull("Certificate for the data was null!", certWrapper.getCertificate());
        assertNotNull("Poison field for the certificate was null!", ((X509Extension) certWrapper.getCertificate()).getExtensionValue("1.3.6.1.4.1.11129.2.4.3"));
        
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
    
    private byte[] fetchSCTList(final List<Certificate> chain, final int minSCTs, final int maxSCTs, final LinkedHashSet<String> labels,
            final int maxRetries) throws CTLogException {
        return fetchSCTList(ct, ctlogs, chain, minSCTs, maxSCTs, labels, maxRetries);
    }
    
    private static byte[] fetchSCTList(final CertificateTransparency ct, final Map<Integer,CTLogInfo> ctlogs, final List<Certificate> chain,
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
    
}
