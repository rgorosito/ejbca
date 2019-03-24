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
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import org.cesecore.CaTestUtils;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateData;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevokedCertInfo;
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
 * A collection of system tests for the VA Queue using EnterpriseValidationAuthorityPublisher, extracted from the Community system tests and VaPublisherQueueTest.java.
 * 
 * @version $Id: VaEnterpriseValidationAuthorityPublisherQueueTest.java 27740 2018-04-30 07:24:53Z andrey_s_helmes $
 *
 */
public class VaEnterpriseValidationAuthorityPublisherQueueTest extends VaPublisherTestBase {

    private final String publisherName = "TEST_EVA_PUBLISHER_QUEUE";
    private EnterpriseValidationAuthorityPublisher enterpriseValidationAuthorityPublisher;
    private int publisherId = 0;
    // Set of variables to track for objects to be removed as test results
    private Certificate testCertificate;
    private List<Integer> publishers;
    private final List<String> publisherQueueFingerprints = new ArrayList<>();
    private String caName = null;
    private String endEntityManagementUsername = null;
    private final List<String> certificateProfileUsernames = new ArrayList<>();
    private X509Certificate x509Certificate = null;
    private String endEntityProfileUsername = null;

    @Rule
    public TestRule traceLogMethodsRule = new TraceLogMethodsRule();

    @Before
    public void setUp() throws CertificateParsingException, PublisherExistsException, AuthorizationDeniedException {
        testCertificate = CertTools.getCertfromByteArray(testCertificateBytes, Certificate.class);
        publishers = new ArrayList<>();
        enterpriseValidationAuthorityPublisher = createEnterpriseValidationAuthorityPublisher();
        publisherId = publisherProxySession.addPublisher(
                internalAdminToken,
                publisherName,
                enterpriseValidationAuthorityPublisher);
        publishers.add(publisherId);
    }
    
    @After
    public void tearDown() throws AuthorizationDeniedException, NoSuchEndEntityException, CouldNotRemoveEndEntityException {
        // Remove certificate
        internalCertStoreSession.removeCertificate(testCertificate);
        // Flush publisher queue
        for(final String fingerprint : publisherQueueFingerprints) {
            for (final PublisherQueueData publisherQueueEntry : publisherQueueSession.getEntriesByFingerprint(fingerprint)) {
                publisherQueueSession.removeQueueData(publisherQueueEntry.getPk());
            }
        }
        // Flush publishers
        publisherProxySession.removePublisherInternal(internalAdminToken, publisherName);
        for (final int publisherEntry : publishers) {
            publisherProxySession.removePublisherInternal(internalAdminToken, publisherProxySession.getPublisherName(publisherEntry));
        }
		
        // Remove CA if exists
        if(caName != null) {
            final CAInfo caInfo = caSession.getCAInfo(internalAdminToken, caName);
            if (caInfo != null && caInfo.getCAToken() != null) {
                cryptoTokenManagementSession.deleteCryptoToken(internalAdminToken, caInfo.getCAToken().getCryptoTokenId());
                caSession.removeCA(internalAdminToken, caInfo.getCAId());
            }
        }
        // Remove end entity if exists
        if(endEntityManagementUsername != null) {
            if (endEntityManagementSession.existsUser(endEntityManagementUsername)) {
                endEntityManagementSession.deleteUser(internalAdminToken, endEntityManagementUsername);
            }
        }
        // Remove certificate profiles if exists
        if(!certificateProfileUsernames.isEmpty()) {
            for(final String certificateProfileUsername : certificateProfileUsernames) {
                certificateProfileSession.removeCertificateProfile(internalAdminToken, certificateProfileUsername);
            }
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
    public void shouldContainActiveCertificateInPublisherQueueInCaseOfPublisherInQueueOnlyMode() throws Exception {
        // given
        publisherProxySession.testConnection(publisherId);
        final String expectedCertificateFingerprint = CertTools.getFingerprintAsString(testCertificateBytes);
        publisherQueueFingerprints.add(expectedCertificateFingerprint);
        // activate only queue
        switchEnterpriseValidationAuthorityPublisherInQueueOnlyMode();
        // when
        final boolean additionResult = publisherSession.storeCertificate(
                internalAdminToken,
                publishers,
                createCertificateDataWrapperUsingTestCertificateData(),
                "foo123",
                CertTools.getSubjectDN(testCertificate),
                null);
        final Collection<PublisherQueueData> publisherQueueCollection = publisherQueueSession.getPendingEntriesForPublisher(publisherId);
        final String actualCertificateFingerprint = extractFirstFingerprintFromPublisherQueue(publisherQueueCollection);
        // then
        assertTrue("Creating External OCSP Publisher failed", publisherId != 0);
        assertFalse("Revoke only mode should be false.", enterpriseValidationAuthorityPublisher.getOnlyPublishRevoked());
        assertFalse("Storing certificate to all external ocsp publisher should return false.", additionResult);
        assertEquals(1, publisherQueueCollection.size());
        assertEquals(expectedCertificateFingerprint, actualCertificateFingerprint);
    }

    @Test
    public void shouldNotContainActiveCertificateInPublisherQueueInQueueOnlyAndRevokedOnlyModes() throws Exception {
        // given
        publisherProxySession.testConnection(publisherId);
        final String expectedCertificateFingerprint = CertTools.getFingerprintAsString(testCertificateBytes);
        publisherQueueFingerprints.add(expectedCertificateFingerprint);
        // activate only queue and only publish when revoked
        switchEnterpriseValidationAuthorityPublisherInQueueOnlyMode();
        switchEnterpriseValidationAuthorityPublisherInRevokedOnlyMode();
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
        assertTrue("Storing ACTIVE certificate to external ocsp publisher that only publishes REVOKED should return true (even though it won't be added to the queue)", additionResult);
        assertEquals("Non revoked certificate should not have been stored in queue", 0, publisherQueueCollection.size());
    }

    @Test
    public void shouldContainRevokedCertificateInPublisherQueueInQueueOnlyAndRevokedOnlyModes() throws Exception {
        // given
        publisherProxySession.testConnection(publisherId);
        final String expectedCertificateFingerprint = CertTools.getFingerprintAsString(testCertificateBytes);
        publisherQueueFingerprints.add(expectedCertificateFingerprint);
        //
        final CertificateData revokedCertificateData = createCertificateDataUsingTestCertificateAndCustomData(
                "test05",
                null,
                CertificateConstants.CERT_REVOKED,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                null,
                null,
                System.currentTimeMillis(),
                RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD,
                System.currentTimeMillis()-1
        );
        // activate only queue and only publish when revoked
        switchEnterpriseValidationAuthorityPublisherInQueueOnlyMode();
        switchEnterpriseValidationAuthorityPublisherInRevokedOnlyMode();
        // when
        final boolean revocationResult = publisherSession.storeCertificate(
                internalAdminToken,
                publishers,
                createCertificateDataWrapperUsingCertificateData(revokedCertificateData),
                "foo123",
                CertTools.getSubjectDN(testCertificate),
                null);
        final Collection<PublisherQueueData> publisherQueueCollection = publisherQueueSession.getPendingEntriesForPublisher(publisherId);
        final String actualCertificateFingerprint = extractFirstFingerprintFromPublisherQueue(publisherQueueCollection);
        // then
        assertFalse("Storing certificate to all external ocsp publisher should return false.", revocationResult);
        assertEquals("Revoked certificate should have been stored in queue", 1, publisherQueueCollection.size());
        assertEquals(expectedCertificateFingerprint, actualCertificateFingerprint);
    }

    @Test
    public void shouldContainRevokedCertificateWithoutRevocationReasonInPublisherQueueInQueueOnlyAndRevokedOnlyModes() throws Exception {
        // given
        publisherProxySession.testConnection(publisherId);
        final String expectedCertificateFingerprint = CertTools.getFingerprintAsString(testCertificateBytes);
        publisherQueueFingerprints.add(expectedCertificateFingerprint);
        //
        final CertificateData revokedCertificateData = createCertificateDataUsingTestCertificateAndCustomData(
                "test05",
                null,
                CertificateConstants.CERT_REVOKED,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                null,
                null,
                System.currentTimeMillis(),
                RevokedCertInfo.NOT_REVOKED,
                -1L
        );
        // activate only queue and only publish when revoked
        switchEnterpriseValidationAuthorityPublisherInQueueOnlyMode();
        switchEnterpriseValidationAuthorityPublisherInRevokedOnlyMode();
        // when
        final boolean revocationResult = publisherSession.storeCertificate(
                internalAdminToken,
                publishers,
                createCertificateDataWrapperUsingCertificateData(revokedCertificateData),
                "foo123",
                CertTools.getSubjectDN(testCertificate),
                null);
        final Collection<PublisherQueueData> publisherQueueCollection = publisherQueueSession.getPendingEntriesForPublisher(publisherId);
        final String actualCertificateFingerprint = extractFirstFingerprintFromPublisherQueue(publisherQueueCollection);
        // then
        assertFalse("Storing certificate to all external ocsp publisher should return false.", revocationResult);
        assertEquals("Revoked certificate should have been stored in queue", 1, publisherQueueCollection.size());
        assertEquals(expectedCertificateFingerprint, actualCertificateFingerprint);
    }

    @Test
    public void shouldContainActiveCertificateWithRevocationReasonRemoveFromCrlInPublisherQueueInQueueOnlyAndRevokedOnlyModes() throws Exception {
        // given
        publisherProxySession.testConnection(publisherId);
        final String expectedCertificateFingerprint = CertTools.getFingerprintAsString(testCertificateBytes);
        publisherQueueFingerprints.add(expectedCertificateFingerprint);
        //
        final CertificateData revokedCertificateData = createCertificateDataUsingTestCertificateAndCustomData(
                "test05",
                null,
                CertificateConstants.CERT_ACTIVE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                null,
                null,
                System.currentTimeMillis(),
                RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL,
                -1L
        );
        // activate only queue and only publish when revoked
        switchEnterpriseValidationAuthorityPublisherInQueueOnlyMode();
        switchEnterpriseValidationAuthorityPublisherInRevokedOnlyMode();
        // when
        final boolean revocationResult = publisherSession.storeCertificate(
                internalAdminToken,
                publishers,
                createCertificateDataWrapperUsingCertificateData(revokedCertificateData),
                "foo123",
                CertTools.getSubjectDN(testCertificate),
                null);
        final Collection<PublisherQueueData> publisherQueueCollection = publisherQueueSession.getPendingEntriesForPublisher(publisherId);
        final String actualCertificateFingerprint = extractFirstFingerprintFromPublisherQueue(publisherQueueCollection);
        // then
        assertFalse("Storing certificate to all external ocsp publisher should return false.", revocationResult);
        assertEquals("Activated certificate (previously on hold) should have been stored in queue", 1, publisherQueueCollection.size());
        assertEquals(expectedCertificateFingerprint, actualCertificateFingerprint);
    }

    @Test
    public void shouldSupportThrowAwayCertificateRevocationAndContainItInPublisherQueueAndInNoConflictsStorageWithProperStatusInQueueOnlyAndRevokedOnlyModes() throws Exception {
        // given
        final int expectedCertificateStatus = CertificateConstants.CERT_REVOKED;
        final int expectedRevocationReason = RevokedCertInfo.REVOCATION_REASON_CACOMPROMISE;
        caName = "testCaTa";
        final String caSubjectDn = "CN="+caName+",C=SE"; 
        final String reverseCaSubjectDn = "C=SE,CN=" + caName;
        final String certificateUsername = "testCaTaUser";
        final String certificateDn = "CN=" + certificateUsername;
        final String certificatePassword = "foo123";
        certificateProfileUsernames.add(caName);
        final int testCaCertificateProfileId = certificateProfileSession.addCertificateProfile(
                internalAdminToken,
                caName,
                createCertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, publisherId, 0,true));
        CaTestUtils.createX509ThrowAwayCa(internalAdminToken, caName, caName, caSubjectDn, testCaCertificateProfileId);
        final CAInfo testCaInfo = caSession.getCAInfo(internalAdminToken, caName);
        final int testCaId =  testCaInfo.getCAId();
        certificateProfileUsernames.add(certificateUsername);
        endEntityProfileUsername = certificateUsername;
        endEntityManagementUsername = certificateUsername;
        final int certificateProfileId = certificateProfileSession.addCertificateProfile(
                internalAdminToken,
                certificateUsername,
                createCertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, publisherId, testCaId,true));
        final int endEntityProfileId = endEntityProfileSession.addEndEntityProfile(internalAdminToken, certificateUsername, createEndEntityProfile(certificateProfileId, testCaId));
        x509Certificate = createThrowAwayX509Certificate(certificateUsername, certificatePassword, certificateDn, endEntityProfileId, certificateProfileId, testCaId);
        // activate only queue and only publish when revoked
        switchEnterpriseValidationAuthorityPublisherInQueueOnlyMode();
        switchEnterpriseValidationAuthorityPublisherInRevokedOnlyMode();
        // when
        endEntityManagementSession.revokeCert(internalAdminToken, x509Certificate.getSerialNumber(), new Date(), caSubjectDn, expectedRevocationReason, false);
        final Collection<PublisherQueueData> publisherQueueCollection = publisherQueueSession.getPendingEntriesForPublisher(publisherId);
        final CertificateDataWrapper actualCertificateDataWrapper = noConflictCertificateStoreSession.getCertificateDataByIssuerAndSerno(caSubjectDn, x509Certificate.getSerialNumber());
        //Assert that the DN order does not matter for this command
        assertNotNull("Regression: could not retrive certificate using reversed CA DN. ", noConflictCertificateStoreSession.getCertificateDataByIssuerAndSerno(reverseCaSubjectDn, x509Certificate.getSerialNumber()));
        final String actualCertificateFingerprint = extractFirstFingerprintFromPublisherQueue(publisherQueueCollection);
        // then
        assertTrue("Creating External OCSP Publisher failed.", 0 != publisherId);
        assertNotNull("Cannot issue a throw-away certificate.", x509Certificate);
        assertEquals("Revoked throw-away certificate should have been stored in queue.", 1, publisherQueueCollection.size());
        assertNotNull("The revoked throw-away certificate should exist in NoConflictsCertificateData", actualCertificateDataWrapper);
        publisherQueueFingerprints.add(actualCertificateDataWrapper.getBaseCertificateData().getFingerprint());
        assertEquals("The fingerprint of certificate in NoConflictsCertificateData and PublisherQueue should match.",
                actualCertificateDataWrapper.getBaseCertificateData().getFingerprint(), actualCertificateFingerprint);
        assertEquals(expectedCertificateStatus, actualCertificateDataWrapper.getBaseCertificateData().getStatus());
        assertEquals(expectedRevocationReason, actualCertificateDataWrapper.getBaseCertificateData().getRevocationReason());
    }

    private void switchEnterpriseValidationAuthorityPublisherInQueueOnlyMode() throws AuthorizationDeniedException {
        enterpriseValidationAuthorityPublisher.setOnlyUseQueue(true);
        publisherSession.changePublisher(internalAdminToken, publisherName, enterpriseValidationAuthorityPublisher);
    }

    private void switchEnterpriseValidationAuthorityPublisherInRevokedOnlyMode() throws AuthorizationDeniedException {
        enterpriseValidationAuthorityPublisher.setPropertyData(enterpriseValidationAuthorityPublisher.getPropertyData() + EnterpriseValidationAuthorityPublisher.PROPERTYKEY_ONLYREVOKED + "=" + true + "\n");
        publisherSession.changePublisher(internalAdminToken, publisherName, enterpriseValidationAuthorityPublisher);
    }

    private String extractFirstFingerprintFromPublisherQueue(final Collection<PublisherQueueData> publisherQueueCollection) {
        if(publisherQueueCollection != null && publisherQueueCollection.size() > 0) {
            return publisherQueueCollection.iterator().next().getFingerprint();
        }
        return null;
    }

}
