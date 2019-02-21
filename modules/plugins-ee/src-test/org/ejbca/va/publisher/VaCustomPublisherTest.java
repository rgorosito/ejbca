/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.va.publisher;

import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.util.ArrayList;
import java.util.List;

import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateData;
import org.cesecore.certificates.certificate.CertificateInfo;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.TraceLogMethodsRule;
import org.ejbca.core.model.ca.publisher.CustomPublisherContainer;
import org.ejbca.core.model.ca.publisher.PublisherConnectionException;
import org.ejbca.core.model.ca.publisher.PublisherExistsException;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * A collection of system tests for the VA Publisher using CustomPublisherContainer, extracted from the org.ejbca.core.model.ca.publisher.PublisherTest and VaPublisherTest.
 *
 * @version $Id: VaCustomPublisherTest.java 28854 2018-05-07 05:40:44Z andrey_s_helmes $
 */
public class VaCustomPublisherTest extends VaPublisherTestBase {

    private int publisherId = 0;
    // Set of variables to track for objects to be removed as test results
    private Certificate testCertificate;
    private List<Integer> publishers;

    @Rule
    public TestRule traceLogMethodsRule = new TraceLogMethodsRule();

    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    @Before
    public void setUp() throws CertificateParsingException, PublisherExistsException, AuthorizationDeniedException {
        testCertificate = CertTools.getCertfromByteArray(testCertificateBytes, Certificate.class);
        publishers = new ArrayList<>();
        String publisherName = "TEST_PUBLISHER";
        CustomPublisherContainer publisherContainer = createCustomPublisherContainer();
        publisherId = publisherProxySession.addPublisher(
                internalAdminToken,
                publisherName,
                publisherContainer);
        publishers.add(publisherId);
    }

    @After
    public void tearDown() throws AuthorizationDeniedException {
        // Remove certificate
        internalCertStoreSession.removeCertificate(testCertificate);
        // Flush publishers
        for (int publisherEntry : publishers) {
            publisherProxySession.removePublisherInternal(internalAdminToken, publisherProxySession.getPublisherName(publisherEntry));
        }
    }

    @Test
    public void shouldSupportCertificateAdditionAndRevocation() throws AuthorizationDeniedException, PublisherConnectionException, CertificateException {
        // given
        publisherProxySession.testConnection(publisherId);
        final CertificateData revokedCertificateData = createCertificateDataUsingTestCertificateAndCustomData(
                "dummyUser",
                null,
                CertificateConstants.CERT_REVOKED,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                null,
                null,
                System.currentTimeMillis(),
                RevokedCertInfo.REVOCATION_REASON_CACOMPROMISE,
                System.currentTimeMillis() - 1
        );
        // when
        final boolean additionResult = publisherSession.storeCertificate(
                internalAdminToken,
                publishers,
                createCertificateDataWrapperUsingTestCertificateData(),
                "foo123",
                CertTools.getSubjectDN(testCertificate),
                null);
        final boolean revocationResult = publisherSession.storeCertificate(
                internalAdminToken,
                publishers,
                createCertificateDataWrapperUsingCertificateData(revokedCertificateData),
                "foo123",
                CertTools.getSubjectDN(testCertificate),
                null);
        // then
        assertTrue("Error storing certificate to external ocsp publisher", additionResult);
        assertTrue("Error storing certificate to external ocsp publisher", revocationResult);
    }

    @Test
    public void shouldProperlyAddCertificateAndHaveCorrectData() throws Exception {
        // given
        publisherProxySession.testConnection(publisherId);
        final String expectedUsername = "someUser";
        final String expectedCaFingerprint = "Some CA fingerprint";
        final int expectedStatus = CertificateConstants.CERT_ACTIVE;
        final int expectedProfileId = CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER;
        final String expectedCsr = "someCsr";
        final String expectedTag = "someTag";
        long expectedTime = System.currentTimeMillis();
        final int expectedRevocationReason = RevokedCertInfo.NOT_REVOKED;
        final CertificateData addCertificateData = createCertificateDataUsingTestCertificateAndCustomData(
                expectedUsername,
                expectedCaFingerprint,
                expectedStatus,
                expectedProfileId,
                expectedCsr,
                expectedTag,
                expectedTime,
                expectedRevocationReason,
                -1L
        );
        // when
        final boolean additionResult = publisherSession.storeCertificate(
                internalAdminToken,
                publishers,
                createCertificateDataWrapperUsingCertificateData(addCertificateData),
                "foo123",
                CertTools.getSubjectDN(testCertificate),
                null);
        final CertificateInfo actualCertificateInfo = certificateStoreSession.getCertificateInfo(CertTools.getFingerprintAsString(testCertificate));
        // then
        assertNotNull("The certificate must be in DB.", actualCertificateInfo);
        assertTrue("Error storing certificate to external ocsp publisher", additionResult);
        assertEquals(expectedStatus, actualCertificateInfo.getStatus());
        assertEquals(expectedRevocationReason, actualCertificateInfo.getRevocationReason());
        assertEquals(expectedProfileId, actualCertificateInfo.getCertificateProfileId());
        assertEquals(expectedTag, actualCertificateInfo.getTag());
        assertEquals(expectedTime, actualCertificateInfo.getUpdateTime().getTime());
        assertEquals(expectedUsername, actualCertificateInfo.getUsername());
        assertEquals(expectedCaFingerprint, actualCertificateInfo.getCAFingerprint());
        final byte[] subjectKeyId = KeyTools.createSubjectKeyId(testCertificate.getPublicKey()).getKeyIdentifier();
        final String keyIdStr = new String(Base64.encode(subjectKeyId));
        assertEquals(keyIdStr, actualCertificateInfo.getSubjectKeyId());
    }

    @Test
    public void shouldProperlyRevokeCertificateAndHaveCorrectData() throws Exception {
        // given
        publisherProxySession.testConnection(publisherId);
        final String expectedUsername = "someUser";
        final String expectedCaFingerprint = "Some CA fingerprint";
        final int expectedStatus = CertificateConstants.CERT_REVOKED;
        final String expectedCsr = "someCsr";
        final String expectedTag = "someTag";
        final int expectedCertificateProfileId = 12345;
        long expectedRevocationTime = System.currentTimeMillis() + 12345;
        final boolean additionResult = publisherSession.storeCertificate(
                internalAdminToken,
                publishers,
                createCertificateDataWrapperUsingTestCertificateData(),
                "foo123",
                CertTools.getSubjectDN(testCertificate),
                null);
        final CertificateData revokedCertificateData = createCertificateDataUsingTestCertificateAndCustomData(
                expectedUsername,
                expectedCaFingerprint,
                CertificateConstants.CERT_REVOKED,
                expectedCertificateProfileId,
                expectedCsr,
                expectedTag,
                expectedRevocationTime,
                RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED,
                expectedRevocationTime
        );
        // when
        final boolean revocationResult = publisherSession.storeCertificate(
                internalAdminToken,
                publishers,
                createCertificateDataWrapperUsingCertificateData(revokedCertificateData),
                "foo123",
                CertTools.getSubjectDN(testCertificate),
                null);
        final CertificateInfo actualCertificateInfo = certificateStoreSession.getCertificateInfo(CertTools.getFingerprintAsString(testCertificate));
        // then
        assertTrue("Error storing certificate to external ocsp publisher", additionResult);
        assertTrue("Error storing certificate to external ocsp publisher", revocationResult);
        assertEquals(expectedStatus, actualCertificateInfo.getStatus());
        assertEquals(expectedCertificateProfileId, actualCertificateInfo.getCertificateProfileId());
        assertEquals(expectedTag, actualCertificateInfo.getTag());
        assertEquals(expectedRevocationTime, actualCertificateInfo.getUpdateTime().getTime());
        assertEquals(expectedUsername, actualCertificateInfo.getUsername());
        assertEquals(expectedCaFingerprint, actualCertificateInfo.getCAFingerprint());
    }

}
