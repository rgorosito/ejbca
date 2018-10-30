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

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.*;
import org.cesecore.certificates.certificate.request.SimpleRequestMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.DatabaseConfiguration;
import org.ejbca.config.InternalConfiguration;
import org.ejbca.core.ejb.ca.publisher.PublisherProxySessionRemote;
import org.ejbca.core.ejb.ca.publisher.PublisherQueueProxySessionRemote;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionRemote;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.ca.publisher.CustomPublisherContainer;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;

import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collections;

/**
 * An intermediate class to support VA Publisher test scenarios and unify common operations.
 *
 * @version $Id: VaPublisherTestBase.java 27422 2018-04-30 14:05:42Z andrey_s_helmes $
 */
public class VaPublisherTestBase {

    static final byte[] testCertificateBytes = Base64.decode(("MIICWzCCAcSgAwIBAgIIJND6Haa3NoAwDQYJKoZIhvcNAQEFBQAwLzEPMA0GA1UE"
            + "AxMGVGVzdENBMQ8wDQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFMB4XDTAyMDEw"
            + "ODA5MTE1MloXDTA0MDEwODA5MjE1MlowLzEPMA0GA1UEAxMGMjUxMzQ3MQ8wDQYD"
            + "VQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFMIGdMA0GCSqGSIb3DQEBAQUAA4GLADCB"
            + "hwKBgQCQ3UA+nIHECJ79S5VwI8WFLJbAByAnn1k/JEX2/a0nsc2/K3GYzHFItPjy"
            + "Bv5zUccPLbRmkdMlCD1rOcgcR9mmmjMQrbWbWp+iRg0WyCktWb/wUS8uNNuGQYQe"
            + "ACl11SAHFX+u9JUUfSppg7SpqFhSgMlvyU/FiGLVEHDchJEdGQIBEaOBgTB/MA8G"
            + "A1UdEwEB/wQFMAMBAQAwDwYDVR0PAQH/BAUDAwegADAdBgNVHQ4EFgQUyxKILxFM"
            + "MNujjNnbeFpnPgB76UYwHwYDVR0jBBgwFoAUy5k/bKQ6TtpTWhsPWFzafOFgLmsw"
            + "GwYDVR0RBBQwEoEQMjUxMzQ3QGFuYXRvbS5zZTANBgkqhkiG9w0BAQUFAAOBgQAS"
            + "5wSOJhoVJSaEGHMPw6t3e+CbnEL9Yh5GlgxVAJCmIqhoScTMiov3QpDRHOZlZ15c"
            + "UlqugRBtORuA9xnLkrdxYNCHmX6aJTfjdIW61+o/ovP0yz6ulBkqcKzopAZLirX+"
            + "XSWf2uI9miNtxYMVnbQ1KPdEAt7Za3OQR6zcS0lGKg==").getBytes());
    static final byte[] testOcpsSignerCertificateBytes = Base64.decode(("MIIDWzCCAkOgAwIBAgIIdoCW+AzvbDcwDQYJKoZIhvcNAQELBQAwOzEVMBMGA1UE" + 
            "AwwMTWFuYWdlbWVudENBMRUwEwYDVQQKDAxFSkJDQSBTYW1wbGUxCzAJBgNVBAYT" + 
            "AlNFMB4XDTE4MDUyNDE0MTYxNFoXDTI4MDUyMTE0MTYxNFowOzEVMBMGA1UEAwwM" + 
            "TWFuYWdlbWVudENBMRUwEwYDVQQKDAxFSkJDQSBTYW1wbGUxCzAJBgNVBAYTAlNF" + 
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwv+AfS+WZgMsEWW/wChn" + 
            "U708FwH7q1ShCN+8PMpf4+r4fZ3qTN4PEvp0eTyOxjK9WcFnAwHIrjbCfCKJyJUM" + 
            "6OA0rovdf28SzGW+iEl3pEK9I5OGjJ6BKzAs1uAjVs/gSSYeYwAcsdv+caGB07Ss" + 
            "bpdF7zPR3O7uknP6OsQRlcf4pw561NWV4MjyXXjQLJbQCDl9WcfLA7g27oljitb4" + 
            "g4mzKzAx3ftS03M1BRq30bpXLoH6ZBhH5mWM27EC8A37PPGg2ds8mDC8Hd0PKVdU" + 
            "qoS70nsHXFVjwWYteKJUzP0mr9o4GLND7LscwGFWnxy3+bGHY9Fs3Iaz1OPrd1fe" + 
            "yQIDAQABo2MwYTAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFCmPt5ioZ43P" + 
            "8i6c1gLDYNaCo8xMMB0GA1UdDgQWBBQpj7eYqGeNz/IunNYCw2DWgqPMTDAOBgNV" + 
            "HQ8BAf8EBAMCAYYwDQYJKoZIhvcNAQELBQADggEBAIuGPMrM4cy8ijpAwJLWqWxy" + 
            "rtoH2Xck6DQ+cyuMIZTtxbB/N32YHnAcyAsSlV1OZw5NmTGSP+Rd+rURiP2ZBYIF" + 
            "QoZpCZS6XFctLNTM3Mqr7Xg7m7uu34kmt6uwRlulURCRCsBc8kRp+6oxVAkUOo+y" + 
            "xerdRt3dlCdSSVffMw96RDIUMI/3SwfPqv8EXUzFo8POYsWbfdZQQqA9PpKMJM22" + 
            "q2oEjh+0B6zoqLPJL/1riHQVKRv7T6MhLycV3vcpvSWs3nI1NEBMZvg6XjkXgGea" + 
            "82k6FNP7M7hKXqymILMTXWValfAqIzfRAgkB+Eob4HWJ8LfsjmlNuuNcsfdQmVo=").getBytes());
    static final AuthenticationToken internalAdminToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("VaPublisherTest"));
    private static final Logger log = Logger.getLogger(VaPublisherTestBase.class);
    //
    protected final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    protected final CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    protected final CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    protected final ConfigurationSessionRemote configurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ConfigurationSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    protected final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class);
    protected final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    protected final EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
    protected final InternalCertificateStoreSessionRemote internalCertStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    protected final NoConflictCertificateStoreSessionRemote noConflictCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(NoConflictCertificateStoreSessionRemote.class);
    protected final PublisherSessionRemote publisherSession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherSessionRemote.class);
    protected final PublisherQueueProxySessionRemote publisherQueueSession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherQueueProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    protected final PublisherProxySessionRemote publisherProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    protected final SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);

    CustomPublisherContainer createCustomPublisherContainer() {
        return createCustomPublisherContainer(
                configurationSession.getProperty(InternalConfiguration.CONFIG_DATASOURCENAMEPREFIX),
                configurationSession.getProperty(DatabaseConfiguration.CONFIG_DATASOURCENAME));
    }

    CustomPublisherContainer createCustomPublisherContainer(final String jndiName) {
        return createCustomPublisherContainer(
                configurationSession.getProperty(InternalConfiguration.CONFIG_DATASOURCENAMEPREFIX),
                jndiName);
    }

    private CustomPublisherContainer createCustomPublisherContainer(final String jndiNamePrefix, final String jndiName) {
        CustomPublisherContainer publisherContainer = new CustomPublisherContainer();
        publisherContainer.setClassPath(EnterpriseValidationAuthorityPublisher.class.getName());
        log.debug("jndiNamePrefix=" + jndiNamePrefix + " jndiName=" + jndiName);
        publisherContainer.setPropertyData("dataSource " + jndiNamePrefix + jndiName);
        publisherContainer.setDescription("Used in Junit Test, Remove this one");
        return publisherContainer;
    }

    EnterpriseValidationAuthorityPublisher createEnterpriseValidationAuthorityPublisher() {
        EnterpriseValidationAuthorityPublisher enterpriseValidationAuthorityPublisher = new EnterpriseValidationAuthorityPublisher();
        final String jndiNamePrefix = configurationSession.getProperty(InternalConfiguration.CONFIG_DATASOURCENAMEPREFIX);
        final String jndiName = configurationSession.getProperty(DatabaseConfiguration.CONFIG_DATASOURCENAME);
        log.debug("jndiNamePrefix=" + jndiNamePrefix + " jndiName=" + jndiName);
        enterpriseValidationAuthorityPublisher.setPropertyData(EnterpriseValidationAuthorityPublisher.PROPERTYKEY_DATASOURCE + "=" + (jndiNamePrefix + jndiName) + "\n");
        enterpriseValidationAuthorityPublisher.setDescription("Used in Junit Test, Remove this one");
        return enterpriseValidationAuthorityPublisher;
    }

    private CertificateData createCertificateDataUsingTestCertificate() throws CertificateParsingException {
        return createCertificateDataUsingTestCertificateAndCustomData(
                "test05",
                null,
                CertificateConstants.CERT_ACTIVE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                null,
                System.currentTimeMillis(),
                RevokedCertInfo.NOT_REVOKED,
                -1L
        );
    }

    CertificateData createCertificateDataUsingTestCertificateAndCustomData(
            final String username,
            final String cafp,
            final int certificateStatus,
            final int certificateProfileId,
            final String tag,
            final long updateTime,
            final int certificateRevocationReason,
            final long certificateRevocationDate) throws CertificateParsingException {
        final Certificate certificate = CertTools.getCertfromByteArray(testCertificateBytes, Certificate.class);
        final CertificateData certificateData = new CertificateData(
                certificate,
                certificate.getPublicKey(),
                username,
                cafp,
                certificateStatus,
                CertificateConstants.CERTTYPE_ENDENTITY,
                certificateProfileId,
                EndEntityConstants.NO_END_ENTITY_PROFILE,
                tag,
                updateTime,
                true,
                true);
        certificateData.setRevocationReason(certificateRevocationReason);
        certificateData.setRevocationDate(certificateRevocationDate);
        return certificateData;
    }

    CertificateDataWrapper createCertificateDataWrapperUsingTestCertificateData() throws CertificateParsingException {
        return createCertificateDataWrapperUsingCertificateData(createCertificateDataUsingTestCertificate());
    }

    CertificateDataWrapper createCertificateDataWrapperUsingCertificateData(final CertificateData certificateData) {
        return new CertificateDataWrapper(certificateData, null);
    }

    CertificateProfile createCertificateProfile(final int certificateProfileType, final int publisherId, final int caId, final boolean isThrowAwayCa) {
        final CertificateProfile certificateProfile = new CertificateProfile(certificateProfileType);
        if(caId != 0) {
            certificateProfile.setAvailableCAs(Collections.singletonList(caId));
        }
        if(isThrowAwayCa) {
            certificateProfile.setUseCertificateStorage(false);
            certificateProfile.setStoreCertificateData(false);
        }
        certificateProfile.setPublisherList(Collections.singletonList(publisherId));
        return certificateProfile;
    }

    EndEntityProfile createEndEntityProfile(final int certificateProfileId, final int caId) {
        final EndEntityProfile endEntityProfile = new EndEntityProfile();
        endEntityProfile.setDefaultCertificateProfile(certificateProfileId);
        endEntityProfile.setAvailableCertificateProfileIds(Collections.singletonList(certificateProfileId));
        endEntityProfile.setDefaultCA(caId);
        endEntityProfile.setAvailableCAs(Collections.singletonList(caId));
        return endEntityProfile;
    }

    EndEntityInformation createEndEntityInformation(final String username, final String dn, final int caId, final int endEntityProfileId, final int certificateProfileId, final String password) {
        final EndEntityInformation endEntityInformation = new EndEntityInformation(
                username,
                dn,
                caId,
                null,
                null,
                new EndEntityType(EndEntityTypes.ENDUSER),
                endEntityProfileId,
                certificateProfileId,
                EndEntityConstants.TOKEN_USERGEN,
                0,
                null);
        endEntityInformation.setPassword(password);
        return endEntityInformation;
    }

    X509Certificate createThrowAwayX509Certificate(
            final String certificateUsername,
            final String certificatePassword,
            final String certificateDn,
            final int endEntityProfileId,
            final int certificateProfileId,
            final int caId) throws Exception {

        final EndEntityInformation endEntityInformation = createEndEntityInformation(
                certificateUsername,
                certificateDn,
                caId,
                endEntityProfileId,
                certificateProfileId,
                certificatePassword
        );
        endEntityManagementSession.addUser(internalAdminToken, endEntityInformation, false);
        final KeyPair keyPair = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        final SimpleRequestMessage simpleRequestMessage = new SimpleRequestMessage(keyPair.getPublic(), endEntityInformation.getUsername(), endEntityInformation.getPassword());
        final X509ResponseMessage x509ResponseMessage = (X509ResponseMessage) signSession.createCertificate(internalAdminToken, simpleRequestMessage, X509ResponseMessage.class, endEntityInformation);
        X509Certificate x509Certificate = (X509Certificate) x509ResponseMessage.getCertificate();
        // Remove this certificate (saved by publisher), however reuse the result
        internalCertStoreSession.removeCertificate(x509Certificate);
        return x509Certificate;
    }
}
