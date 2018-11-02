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
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
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

    @Rule
    public TestRule traceLogMethodsRule = new TraceLogMethodsRule();
    
    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    @Ignore
    @Test
    public void testScpFunctionality() throws PublisherException, OperatorCreationException, CertificateException, InvalidAlgorithmParameterException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
        ScpPublisher scpPublisher = new ScpPublisher();
        Properties properties = new Properties();
        properties.setProperty(ScpPublisher.ANONYMIZE_CERTIFICATES_PROPERTY_NAME, "false");
        properties.setProperty(ScpPublisher.CERT_SCP_DESTINATION_PROPERTY_NAME, "download.primekey.com:tmp");
        properties.setProperty(ScpPublisher.CRL_SCP_DESTINATION_PROPERTY_NAME, "download.primekey.com:tmp");
        properties.setProperty(ScpPublisher.SCP_PRIVATE_KEY_PROPERTY_NAME, "/Users/mikek/.ssh/id_rsa");
        properties.setProperty(ScpPublisher.SCP_KNOWN_HOSTS_PROPERTY_NAME, "/Users/mikek/.ssh/known_hosts");
        properties.setProperty(ScpPublisher.SSH_USERNAME, "mikek");
        String password = "yourpassword";
        properties.setProperty(ScpPublisher.SCP_PRIVATE_KEY_PASSWORD, StringTools.pbeEncryptStringWithSha256Aes192(password));
        scpPublisher.init(properties);
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA); 
        X509Certificate certificate = CertTools.genSelfCert("C=SE,O=PrimeKey,CN=ScpPublisherTest", 365, null, keys.getPrivate(), keys.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true);        
        scpPublisher.storeCertificate(null, certificate, null, null, null, null, CertificateConstants.CERT_REVOKED, 
                CertificateConstants.CERTTYPE_ENDENTITY, 0, 0, null, 0, 0, null);
        //To check that publisher works, verify that the published certificate exists at the location
    }

}
