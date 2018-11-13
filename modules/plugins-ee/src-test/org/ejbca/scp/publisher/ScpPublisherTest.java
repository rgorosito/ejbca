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
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.crl.RevocationReasons;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.StringTools;
import org.cesecore.util.TraceLogMethodsRule;
import org.ejbca.core.model.ca.publisher.PublisherException;
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

    @Ignore
    @Test
    public void testPublishCertificate() throws PublisherException, OperatorCreationException, CertificateException, InvalidAlgorithmParameterException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
        ScpPublisher scpPublisher = new ScpPublisher();
        Properties properties = new Properties();
        properties.setProperty(ScpPublisher.SIGNING_CA_PROPERTY_NAME, "1652389506");
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
