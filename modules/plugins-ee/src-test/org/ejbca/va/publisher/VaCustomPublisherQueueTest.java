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

import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.cesecore.CaTestUtils;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.certificate.CertificateData;
import org.cesecore.certificates.certificate.request.SimpleRequestMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.TraceLogMethodsRule;
import org.ejbca.core.ejb.ra.CouldNotRemoveEndEntityException;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.ca.publisher.PublisherExistsException;
import org.ejbca.core.model.ca.publisher.PublisherQueueData;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * A collection of system tests for the VA Queue using CustomPublisherContainer, extracted from the Community system tests and VaPublisherQueueTest.java.
 *
 * @version $Id: VaCustomPublisherQueueTest.java 27740 2018-04-30 07:24:53Z andrey_s_helmes $
 *
 */
public class VaCustomPublisherQueueTest extends VaPublisherTestBase {

    private int publisherId = 0;
    // Set of variables to track for objects to be removed as test results
    private Certificate testCertificate;
    private List<Integer> publishers;
    private String caName = null;
    private String endEntityManagementUsername = null;
    private String certificateProfileUsername = null;
    private X509Certificate x509Certificate = null;
    private String endEntityProfileUsername = null;
    private List<String> publisherQueueFingerprints;

    @Rule
    public TestRule traceLogMethodsRule = new TraceLogMethodsRule();

    @Before
    public void setUp() throws CertificateParsingException, PublisherExistsException, AuthorizationDeniedException {
        testCertificate = CertTools.getCertfromByteArray(testCertificateBytes, Certificate.class);
        publishers = new ArrayList<>();
        String publisherName = "TEST_PUBLISHER_QUEUE";
        publisherId = publisherProxySession.addPublisher(
                internalAdminToken,
                publisherName,
                createCustomPublisherContainer());
        publishers.add(publisherId);
        publisherQueueFingerprints = new ArrayList<>();
    }

    @After
    public void tearDown() throws AuthorizationDeniedException, NoSuchEndEntityException, CouldNotRemoveEndEntityException {
        // Remove certificate
        internalCertStoreSession.removeCertificate(testCertificate);
        // Flush publisher queue
        for(String fingerprint : publisherQueueFingerprints) {
            for (PublisherQueueData publisherQueueEntry : publisherQueueSession.getEntriesByFingerprint(fingerprint)) {
                publisherQueueSession.removeQueueData(publisherQueueEntry.getPk());
            }
        }
        // Flush publishers
        for(int publisherEntry : publishers) {
            publisherProxySession.removePublisherInternal(internalAdminToken, publisherProxySession.getPublisherName(publisherEntry));
        }
        // Remove CA if exists
        if(caName != null) {
            final CAInfo caInfo = caSession.getCAInfo(internalAdminToken, caName);
            cryptoTokenManagementSession.deleteCryptoToken(internalAdminToken, caInfo.getCAToken().getCryptoTokenId());
            caSession.removeCA(internalAdminToken, caInfo.getCAId());
        }
        // Remove end entity if exists
        if(endEntityManagementUsername != null) {
            if (endEntityManagementSession.existsUser(endEntityManagementUsername)) {
                endEntityManagementSession.deleteUser(internalAdminToken, endEntityManagementUsername);
            }
        }
        // Remove certificate profile if exists
        if(certificateProfileUsername != null) {
            certificateProfileSession.removeCertificateProfile(internalAdminToken, certificateProfileUsername);
        }
        // Remove certificate if exists
        if(x509Certificate != null) {
            internalCertStoreSession.removeCertificate(x509Certificate);
        }
        // Remove end entity profile if exists
        if(endEntityProfileUsername != null) {
            endEntityProfileSession.removeEndEntityProfile(internalAdminToken, endEntityProfileUsername);
        }
    }

    @Test
    public void shouldContainAddedCertificateInPublisherQueueInCaseOfPublisherFailure() throws Exception {
        // given
        final String expectedCertificateFingerprint = CertTools.getFingerprintAsString(testCertificateBytes);
        final int badPublisherId = publisherProxySession.addPublisher(
                internalAdminToken,
                "BAD_PUBLISHER",
                createCustomPublisherContainer("NoExist234DS"));
        publishers.add(badPublisherId);
        publisherQueueFingerprints.add(expectedCertificateFingerprint);
        // when
        final boolean result = publisherSession.storeCertificate(
                internalAdminToken,
                publishers,
                createCertificateDataWrapperUsingTestCertificateData(),
                "foo123",
                CertTools.getSubjectDN(testCertificate),
                null);
        final Collection<PublisherQueueData> publisherQueueCollection = publisherQueueSession.getPendingEntriesForPublisher(badPublisherId);
        final String actualCertificateFingerprint = extractFirstFingerprintFromPublisherQueue(publisherQueueCollection);
        // then
        assertTrue("Creating External OCSP Publisher failed", badPublisherId != 0);
        assertFalse("Storing certificate to external ocsp publisher should fail.", result);
        assertEquals(1, publisherQueueCollection.size());
        assertEquals(expectedCertificateFingerprint, actualCertificateFingerprint);
    }

    @Test
    public void shouldContainNewlySignedCertificateInPublisherQueueInCaseOfPublisherFailure() throws Exception {
        // given
        caName = "testExternalOCSPPublisherTransactionFail";
        final String caSubjectDn = "CN=" + caName;
        final String certificateUsername = "testExternalOCSPPublisherTransactionFailUser";
        final String certificateDn = "CN=" + certificateUsername;
        final String certificatePassword = "foo123";
        publisherId = publisherProxySession.addPublisher(
                internalAdminToken,
                "BAD_PUBLISHER",
                createCustomPublisherContainer("NoExist234DS"));
        publishers.add(publisherId);
        CaTestUtils.createActiveX509Ca(internalAdminToken, caName, caName, caSubjectDn);
        final CAInfo testCa = caSession.getCAInfo(internalAdminToken, caName);
        certificateProfileUsername = certificateUsername;
        final int certificateProfileId = certificateProfileSession.addCertificateProfile(
                internalAdminToken,
                certificateUsername,
                createCertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, publisherId, 0, false));
        endEntityProfileUsername = certificateUsername;
        final int endEntityProfileId = endEntityProfileSession.addEndEntityProfile(
                internalAdminToken,
                certificateUsername,
                createEndEntityProfile(certificateProfileId, testCa.getCAId()));
        final EndEntityInformation endEntityInformation = createEndEntityInformation(
                certificateUsername,
                certificateDn,
                testCa.getCAId(),
                endEntityProfileId,
                certificateProfileId,
                certificatePassword
        );
        endEntityManagementUsername = certificateUsername;
        endEntityManagementSession.addUser(internalAdminToken, endEntityInformation, false);
        final KeyPair keyPair = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        final SimpleRequestMessage simpleRequestMessage = new SimpleRequestMessage(keyPair.getPublic(), endEntityInformation.getUsername(), endEntityInformation.getPassword());
        try {
            final X509ResponseMessage x509ResponseMessage = (X509ResponseMessage) signSession.createCertificate(internalAdminToken,
                    simpleRequestMessage, X509ResponseMessage.class, endEntityInformation);
            x509Certificate = (X509Certificate) x509ResponseMessage.getCertificate();
            final String x509CertificateFingerprint = CertTools.getFingerprintAsString(x509Certificate);
            publisherQueueFingerprints.add(x509CertificateFingerprint);
            final CertificateData certificateData = internalCertStoreSession.getCertificateData(x509CertificateFingerprint);
            // when
            final Collection<PublisherQueueData> publisherQueueCollection = publisherQueueSession.getPendingEntriesForPublisher(publisherId);
            final String actualCertificateFingerprint = extractFirstFingerprintFromPublisherQueue(publisherQueueCollection);
            // then
            assertTrue("Creating External OCSP Publisher failed", 0 != publisherId);
            assertNotNull("Response shouldn't be null even if publishing failed.", x509ResponseMessage);
            assertNotNull("Certificate storage was rolled back.", certificateData);
            assertEquals(1, publisherQueueCollection.size());
            assertEquals(CertTools.getFingerprintAsString(x509Certificate), actualCertificateFingerprint);
        } finally {
            internalCertStoreSession.removeCertificatesByUsername(certificateUsername);
        }
    }

    @Test
    public void shouldNotContainAddedCertificateInPublisherQueueInCaseOfOperationalPublisher() throws Exception {
        // given
        publisherProxySession.testConnection(publisherId);
        // when
        final boolean additionResult = publisherSession.storeCertificate(
                internalAdminToken,
                publishers,
                createCertificateDataWrapperUsingTestCertificateData(),
                "foo123",
                CertTools.getSubjectDN(testCertificate),
                null);
        final Collection<PublisherQueueData> publisherQueueCollection = publisherQueueSession.getPendingEntriesForPublisher(publisherId);
        // then
        assertTrue("Creating External OCSP Publisher failed", 0 != publisherId);
        assertTrue("Storing certificate to external ocsp publisher should succeed.", additionResult);
        assertEquals(0, publisherQueueCollection.size());
    }

    private String extractFirstFingerprintFromPublisherQueue(final Collection<PublisherQueueData> publisherQueueCollection) {
        if(publisherQueueCollection != null && publisherQueueCollection.size() > 0) {
            return publisherQueueCollection.iterator().next().getFingerprint();
        }
        return null;
    }
}
