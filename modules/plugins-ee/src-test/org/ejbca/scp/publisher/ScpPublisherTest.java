/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.scp.publisher;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Properties;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevocationReasons;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.StringTools;
import org.cesecore.util.TraceLogMethodsRule;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.model.ca.publisher.PublisherException;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;

/**
 * 
 * This test provides some simple boilerplate to test an scp to a known server. Tests are set to ignore until somebody figures out how to makes this test 
 * work universally. 
 * 
 * @version $Id$
 *
 */
public class ScpPublisherTest {

    private static byte[] testCrl = Base64.decode(("MIIBjjB4AgEBMA0GCSqGSIb3DQEBBQUAMBUxEzARBgNVBAMMCkx1bmFDQTEwMjQX"
            +"DTEwMTEyNTEwMzkwMFoXDTEwMTEyNjEwMzkwMFqgLzAtMB8GA1UdIwQYMBaAFHxk"
            +"N9a5Vyro6OD5dXiAbqLfxXo3MAoGA1UdFAQDAgECMA0GCSqGSIb3DQEBBQUAA4IB"
            +"AQCoEY8mTbUwFaHLWYNBhh9q07zhj+2UhN2q/JzJppPonkn8qwnFYAc0MXnLV3et"
            +"TE10N40jx+wxhNzerKi5aPP5VugVZVPRCwhH3ObwZpzQToYaa/ypbXp/7Pnz6K2Y"
            +"n4NVbutNKreBRyoXmyuRB5YaiJII1lTHLOu+NCkUTREVCE3xd+OQ258TTW+qgUgy"
            +"u0VnpowMyEwfkxZQkVXI+9woowKvu07DJmG7pNeAZWRT8ff1pzCERB39qUJExVcn"
            +"g9LkoIo1SpZnHh+oELNJA0PrjYdVzerkG9fhtzo54dVDp9teVUHuJOp9NAG9U3XW"
            +"bBc+OH6NrfpkCWsw9WLdrOK2").getBytes());
    
    @Rule
    public TestRule traceLogMethodsRule = new TraceLogMethodsRule();
    
    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }
    private static final String caName = "ScpPublisherTest";
    private static final String cadn = "CN="+caName;
    
    private AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("ScpPublisherTest"));

    
    /** @return a CAToken for referencing the specified CryptoToken. */
    private static CAToken createCaToken(final int cryptoTokenId, String sigAlg, String encAlg) {
        // Create CAToken (what key in the CryptoToken should be used for what)
        final Properties caTokenProperties = new Properties();
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, CAToken.SOFTPRIVATEDECKEYALIAS);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING_NEXT , CAToken.SOFTPRIVATEDECKEYALIAS);
        final CAToken catoken = new CAToken(cryptoTokenId, caTokenProperties);
        catoken.setSignatureAlgorithm(sigAlg);
        catoken.setEncryptionAlgorithm(encAlg);
        catoken.setKeySequence(CAToken.DEFAULT_KEYSEQUENCE);
        catoken.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
        return catoken;
    }
    
    @Before
    public void setup() throws CAExistsException, CryptoTokenOfflineException, AuthorizationDeniedException {
        final int cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(internalAdmin, caName, String.valueOf(1024));
        CAToken catoken = createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA1_WITH_RSA, AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        X509CAInfo cainfo = new X509CAInfo(cadn, caName, CAConstants.CA_ACTIVE, CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, "3650d",
                CAInfo.SELFSIGNED, null, catoken);
        final CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
        try {
            caAdminSession.createCA(internalAdmin, cainfo);
        } catch (InvalidAlgorithmException e) {
            throw new IllegalArgumentException("Could not create CA.", e);
        }
    }
    
    @After
    public void tearDown() throws AuthorizationDeniedException {
        CaTestCase.removeTestCA(caName);
    }

    @Ignore
    @Test
    public void testPublishCertificate() throws PublisherException, OperatorCreationException, CertificateException, InvalidAlgorithmParameterException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, AuthorizationDeniedException, CADoesntExistsException {
        CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
        CAInfo cainfo = caSession.getCAInfo(internalAdmin, caName);
        CAToken catoken = cainfo.getCAToken();
        catoken.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, "foo");
        cainfo.setCAToken(catoken);
        caSession.editCA(internalAdmin, cainfo);
        ScpPublisher scpPublisher = new ScpPublisher();
        Properties properties = new Properties();
        properties.setProperty(ScpPublisher.SIGNING_CA_PROPERTY_NAME, Integer.toString(cadn.hashCode()));
        properties.setProperty(ScpPublisher.ANONYMIZE_CERTIFICATES_PROPERTY_NAME, "false");
        properties.setProperty(ScpPublisher.CERT_SCP_DESTINATION_PROPERTY_NAME, "download.primekey.com:tmp");
        properties.setProperty(ScpPublisher.CRL_SCP_DESTINATION_PROPERTY_NAME, "download.primekey.com:tmp");
        properties.setProperty(ScpPublisher.SCP_PRIVATE_KEY_PROPERTY_NAME, "/Users/mikek/.ssh/id_rsa");
        properties.setProperty(ScpPublisher.SCP_KNOWN_HOSTS_PROPERTY_NAME, "/Users/mikek/.ssh/known_hosts");
        properties.setProperty(ScpPublisher.SSH_USERNAME, "mikek");
        String password = "";
        properties.setProperty(ScpPublisher.SCP_PRIVATE_KEY_PASSWORD, StringTools.pbeEncryptStringWithSha256Aes192(password));
        scpPublisher.init(properties);
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA); 
        final int reason = RevocationReasons.KEYCOMPROMISE.getDatabaseValue();
        final long date = 1541434399560L;
        final String subjectDn = "C=SE,O=PrimeKey,CN=ScpPublisherTest";
        X509Certificate certificate = CertTools.genSelfCert("C=SE,O=PrimeKey,CN=ScpPublisherTest", 365, null, keys.getPrivate(), keys.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true);     
        TestAlwaysAllowLocalAuthenticationToken testAlwaysAllowLocalAuthenticationToken = new TestAlwaysAllowLocalAuthenticationToken("testPublishCertificate");
        final String username = "ScpContainer";
        final long lastUpdate = 4711L;
        final int certificateProfileId = 1337;
        scpPublisher.storeCertificate(testAlwaysAllowLocalAuthenticationToken, certificate, username, null, subjectDn, null, CertificateConstants.CERT_REVOKED, 
                CertificateConstants.CERTTYPE_ENDENTITY, date, reason, null, certificateProfileId, lastUpdate, null);
        //To check that publisher works, verify that the published certificate exists at the location
    }
    
    @Ignore 
    @Test
    public void testPublishCrl() throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, PublisherException {
        ScpPublisher scpPublisher = new ScpPublisher();
        Properties properties = new Properties();
        properties.setProperty(ScpPublisher.ANONYMIZE_CERTIFICATES_PROPERTY_NAME, "false");
        properties.setProperty(ScpPublisher.CERT_SCP_DESTINATION_PROPERTY_NAME, "download.primekey.com:tmp");
        properties.setProperty(ScpPublisher.CRL_SCP_DESTINATION_PROPERTY_NAME, "download.primekey.com:tmp");
        properties.setProperty(ScpPublisher.SCP_PRIVATE_KEY_PROPERTY_NAME, "/Users/mikek/.ssh/id_rsa");
        properties.setProperty(ScpPublisher.SCP_KNOWN_HOSTS_PROPERTY_NAME, "/Users/mikek/.ssh/known_hosts");
        properties.setProperty(ScpPublisher.SSH_USERNAME, "mikek");
        String password = "";
        properties.setProperty(ScpPublisher.SCP_PRIVATE_KEY_PASSWORD, StringTools.pbeEncryptStringWithSha256Aes192(password));
        scpPublisher.init(properties);
        TestAlwaysAllowLocalAuthenticationToken testAlwaysAllowLocalAuthenticationToken = new TestAlwaysAllowLocalAuthenticationToken("testPublishCrl");
        scpPublisher.storeCRL(testAlwaysAllowLocalAuthenticationToken, testCrl, null, 0, null);
        //To check that publisher works, verify that the published CRL exists at the location

    }

}
