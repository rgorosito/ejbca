/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.model;

import static org.junit.Assert.assertEquals;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.crl.RevocationReasons;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Unit tests for the CertSafePublisher
 * 
 * @version $Id$
 *
 */
public class CertSafePublisherTest {

    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    @Test
    public void testJSonSerialization() throws InvalidAlgorithmParameterException, OperatorCreationException, CertificateException,
            NoSuchMethodException, SecurityException, IllegalAccessException, IllegalArgumentException, InvocationTargetException, ParseException {
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        X509Certificate certificate = CertTools.genSelfCert("C=SE,O=PrimeKey,CN=testJSonSerialization", 365, null, keys.getPrivate(),
                keys.getPublic(), AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true);
        CertSafePublisher certSafePublisher = new CertSafePublisher();
        int status = CertificateConstants.CERT_REVOKED;
        int reason = RevocationReasons.KEYCOMPROMISE.getDatabaseValue();
        long date = 1541434399560L;
        Method getJSONString = CertSafePublisher.class.getDeclaredMethod("getJSONString", Certificate.class, int.class, int.class, long.class);
        getJSONString.setAccessible(true);
        //Certificate, Status, Revocation Reason, Revocation Date
        String jsonDump = (String) getJSONString.invoke(certSafePublisher, certificate, status, reason, date);
        JSONParser parser = new JSONParser();
        JSONObject jsonObject = (JSONObject) parser.parse(jsonDump);
        assertEquals("Revocation reason was not correctly JSON serialized", "keyCompromise",
                jsonObject.get(CertSafePublisher.JSON_REVOCATION_REASON));
        assertEquals("Certificate Status was not correctly JSON serialized", "revoked", jsonObject.get(CertSafePublisher.JSON_STATUS));
        assertEquals("Revocation date was not correctly JSON serialized", "2018-11-05 05:13:19 CET",
                jsonObject.get(CertSafePublisher.JSON_REVOCATION_DATE));
        assertEquals("Certificate was not correctly JSON serialized", CertTools.getPemFromCertificate(certificate),
                jsonObject.get(CertSafePublisher.JSON_CERTIFICATE));
    }

}
