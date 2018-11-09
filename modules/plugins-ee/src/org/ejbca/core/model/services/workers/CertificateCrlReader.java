/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.model.services.workers;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.util.CertTools;
import org.ejbca.core.model.services.BaseWorker;
import org.ejbca.core.model.services.CustomServiceWorkerProperty;
import org.ejbca.core.model.services.CustomServiceWorkerUiSupport;
import org.ejbca.core.model.services.ServiceExecutionFailedException;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.scp.publisher.ScpContainer;

/**
 * This custom worker reads Certificates and CRLs from a local directory periodically and inserts them into the database. 
 * 
 * @version $Id$
 *
 */
public class CertificateCrlReader extends BaseWorker implements CustomServiceWorkerUiSupport {

    private static final Logger log = Logger.getLogger(CertificateCrlReader.class);

    private static final String CERTIFICATE_DIRECTORY_KEY = "certificate.directory";
    private static final String CRL_DIRECTORY_KEY = "crl.directory";
    private static final String SIGNING_CA_ID_KEY = "signing.ca.id";

    private final JcaSignerInfoVerifierBuilder jcaSignerInfoVerifierBuilder;

    public CertificateCrlReader() {
        super();
        try {
            jcaSignerInfoVerifierBuilder = new JcaSignerInfoVerifierBuilder(
                    new JcaDigestCalculatorProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build())
                            .setProvider(BouncyCastleProvider.PROVIDER_NAME);
        } catch (OperatorCreationException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public List<CustomServiceWorkerProperty> getCustomUiPropertyList(AuthenticationToken authenticationToken, Properties currentProperties,
            Map<String, String> languageResource) {
        List<CustomServiceWorkerProperty> workerProperties = new ArrayList<>();
        workerProperties.add(new CustomServiceWorkerProperty(CERTIFICATE_DIRECTORY_KEY, CustomServiceWorkerProperty.UI_TEXTINPUT,
                getCertificateDirectory(currentProperties)));
        workerProperties.add(
                new CustomServiceWorkerProperty(CRL_DIRECTORY_KEY, CustomServiceWorkerProperty.UI_TEXTINPUT, getCRLDirectory(currentProperties)));

        CaSessionLocal caSession = new EjbLocalHelper().getCaSession();
        List<String> authorizedCaIds = new ArrayList<>();
        List<String> authorizedCaNames = new ArrayList<>();
        HashMap<Integer, String> caIdToNameMap = caSession.getCAIdToNameMap();
        authorizedCaIds.add("-1");
        authorizedCaNames.add("None");
        for (Integer caId : caSession.getAuthorizedCaIds(authenticationToken)) {
            authorizedCaIds.add(caId.toString());
            authorizedCaNames.add(caIdToNameMap.get(caId));
        }
        int caId = getCaId(currentProperties);
        workerProperties.add(new CustomServiceWorkerProperty(SIGNING_CA_ID_KEY, CustomServiceWorkerProperty.UI_SELECTONE, authorizedCaIds,
                authorizedCaNames, Integer.valueOf(caId).toString()));

        return workerProperties;
    }

    @Override
    public void work(Map<Class<?>, Object> ejbs) throws ServiceExecutionFailedException {
        //Read certificate directory 
        File certificateDirectory = getDirectory(getCertificateDirectory(properties));
        File crlDirectory = getDirectory(getCRLDirectory(properties));
        final CaSessionLocal caSession = (CaSessionLocal) ejbs.get(CaSessionLocal.class);
        int caId = getCaId(properties);
        List<Certificate> caChain;
        if (caId != -1) {
            CAInfo signingCa;
            try {
                signingCa = caSession.getCAInfo(admin, getCaId(properties));
            } catch (AuthorizationDeniedException e) {
                throw new ServiceExecutionFailedException("Certificate Reader does not have access to CA with id " + getCaId(properties));
            }
            caChain = signingCa.getCertificateChain();
        } else {
            caChain = null;
        }
        if (certificateDirectory != null) {
            if (!certificateDirectory.canRead() || !certificateDirectory.canWrite()) {
                throw new ServiceExecutionFailedException("Certificate Reader lacks read and/or write rights to directory " + certificateDirectory);
            }

            for (final File file : certificateDirectory.listFiles()) {
                final String fileName = file.getName();
                byte[] signedData = null;
                try {
                    FileInputStream fileInputStream = new FileInputStream(file);
                    ByteArrayOutputStream baos = new ByteArrayOutputStream(10000);
                    byte[] buffer = new byte[10000];
                    int bytes;
                    while ((bytes = fileInputStream.read(buffer)) != -1) {
                        baos.write(buffer, 0, bytes);
                    }
                    fileInputStream.close();
                    signedData = baos.toByteArray();
                } catch (IOException e) {
                    log.info("File '" + fileName + "' could not be read.");
                    continue;
                }

                byte[] data;
                try {
                    data = getAndVerifySignedData(signedData, caChain);
                } catch (SignatureException | CertificateException e) {
                    throw new ServiceExecutionFailedException("Could not get/verify signed certificate file", e);
                }
                if (log.isDebugEnabled()) {
                    log.debug("File '" + fileName + "' successfully verified");
                }
                try {
                    storeCertificate(ejbs, data);
                } catch (AuthorizationDeniedException e) {
                    throw new ServiceExecutionFailedException("Service not authorized to store certificates in database.", e);
                }
                if (log.isDebugEnabled()) {
                    log.debug("File '" + fileName + "' successfully decoded");
                }
                file.delete();

            }

        }
    }

    /**
     * Stores the certificate to the database, alternatively only the revocation information if it was anonymized. 
     * 
     * @param ejbs a map of EJB Session Beans
     * @param data a serialized ScpContainer
     * @throws AuthorizationDeniedException if the worker was not auhtorized to write to the certificate table
     * @throws ServiceExecutionFailedException if the ScpContainer object couldn't be deserialized
     */
    private void storeCertificate(final Map<Class<?>, Object> ejbs, final byte[] data)
            throws AuthorizationDeniedException, ServiceExecutionFailedException {
        ScpContainer scpObject = unwrapScpContainer(data);
        final CertificateStoreSessionLocal certificateStoreSession = (CertificateStoreSessionLocal) ejbs.get(CertificateStoreSessionLocal.class);
        final CaSessionLocal caSession = (CaSessionLocal) ejbs.get(CaSessionLocal.class);
        int caId = scpObject.getIssuer().hashCode();
        CAInfo caInfo = caSession.getCAInfoInternal(caId);
        final String caFingerprint = CertTools.getFingerprintAsString(caInfo.getCertificateChain().iterator().next());
        if (scpObject.getCertificate() == null) {
            //Information has been redacted, just write the minimum 
            certificateStoreSession.updateLimitedCertificateDataStatus(admin, caId, scpObject.getIssuer(), scpObject.getSerialNumber(),
                    new Date(scpObject.getRevocationDate()), scpObject.getRevocationReason(), caFingerprint);
        } else {
            final int endEntityProfileId = EndEntityConstants.NO_END_ENTITY_PROFILE;
            final Certificate certificate = scpObject.getCertificate();
            final String username = scpObject.getUsername();
            final int certificateStatus = scpObject.getCertificateStatus();
            final int certificateType = scpObject.getCertificateType();
            final int certificateProfile = scpObject.getCertificateProfile();
            final long updateTime = scpObject.getUpdateTime();
            certificateStoreSession.storeCertificateNoAuth(admin, certificate, username, caFingerprint, certificateStatus, certificateType,
                    certificateProfile, endEntityProfileId, null, updateTime);

        }
    }

    /**
     * 
     * @param data a serialized ScpContainer
     * @return the ScpContainer object
     * @throws ServiceExecutionFailedException if serialization fails for any reason. 
     */
    private ScpContainer unwrapScpContainer(final byte[] data) throws ServiceExecutionFailedException {
        ScpContainer scpObject;
        ByteArrayInputStream bis = new ByteArrayInputStream(data);
        ObjectInput in = null;
        try {
            in = new ObjectInputStream(bis);
            scpObject = (ScpContainer) in.readObject();
            return scpObject;
        } catch (IOException | ClassNotFoundException e) {
            throw new ServiceExecutionFailedException(
                    "Couldn't deserialize ScpContainer, possibly due to a signed ScpContainer being processed without a signing CA declared.", e);
        } finally {
            try {
                if (in != null) {
                    in.close();
                }
            } catch (IOException ex) {
                // NOPMD: ignore close exception
            }
        }
    }

    /**
     * Retrieves a piece of data from within a signed envelope
     * 
     * @param signedData the signed data, as a byte array
     * @param caCerts the signing certificate chain. 
     * @return the byte array in its original form
     * @throws SignatureException if an issue was found with the signature
     * @throws CertificateException if the certificate couldn't be extracted from signedData
     */
    private byte[] getAndVerifySignedData(final byte[] signedData, final List<Certificate> signingCertificateChain)
            throws SignatureException, CertificateException {
        if (signingCertificateChain == null || signingCertificateChain.isEmpty()) {
            //We're going to have to presume that the data wasn't signed at, since no signing CA was provided. 
            return signedData;
        }

        CMSSignedData csd;
        try {
            csd = new CMSSignedData(signedData);
        } catch (CMSException e) {
            throw new SignatureException("Could not unwrap signed byte array.", e);
        }
        Store<X509CertificateHolder> certs = csd.getCertificates();
        SignerInformation signer = (SignerInformation) csd.getSignerInfos().getSigners().iterator().next();
        @SuppressWarnings("unchecked")
        List<X509CertificateHolder> certCollection = (List<X509CertificateHolder>) certs.getMatches(signer.getSID());
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certCollection.get(0));
        try {
            if (!signer.verify(jcaSignerInfoVerifierBuilder.build(cert.getPublicKey()))) {
                throw new SignatureException("Could not verify signature.");
            }
        } catch (OperatorCreationException e) {
            throw new SignatureException("Could not create verified from public key.", e);
        } catch (CMSException e) {
            throw new SignatureException("Signature on data is no longer valid", e);
        }
        for (Certificate caCert : signingCertificateChain) {
            if (cert.getIssuerX500Principal().getName().equals(((X509Certificate) caCert).getSubjectX500Principal().getName())) {
                try {
                    cert.verify(caCert.getPublicKey());
                } catch (CertificateException | InvalidKeyException e) {
                    throw new IllegalStateException("Public key could not be extracted from CA cert.", e);
                } catch (NoSuchAlgorithmException e) {
                    throw new IllegalStateException("Algorithm as provided in CA cert was invalid.", e);
                } catch (NoSuchProviderException e) {
                    throw new IllegalStateException("BouncyCastle was not found as a provider.", e);
                }
                CMSProcessableByteArray cpb = (CMSProcessableByteArray) csd.getSignedContent();
                return (byte[]) cpb.getContent();
            }
        }
        throw new SignatureException("No CA key matching: " + cert.getIssuerX500Principal().getName());
    }

    /**
     * 
     * @param directoryName a local path to a directory
     * @return the directory as a File, or null if it was never defined. 
     * @throws ServiceExecutionFailedException if the directory was defined but does not exist, or is not a directory. 
     */
    private File getDirectory(final String directoryName) throws ServiceExecutionFailedException {
        File directory = null;
        if (StringUtils.isNotEmpty(directoryName)) {
            directory = new File(directoryName);
            if (!directory.exists() || !directory.isDirectory()) {
                final String msg = "Directory '" + directoryName + "' is defined, but not a directory.";
                log.error(msg);
                throw new ServiceExecutionFailedException(msg);
            }
        }
        return directory;
    }

    private String getCertificateDirectory(final Properties properties) {
        return properties.getProperty(CERTIFICATE_DIRECTORY_KEY, "");
    }

    private String getCRLDirectory(final Properties properties) {
        return properties.getProperty(CRL_DIRECTORY_KEY, "");
    }

    private int getCaId(final Properties properties) {
        String propertyValue = properties.getProperty(SIGNING_CA_ID_KEY, "-1");
        if (StringUtils.isNotEmpty(propertyValue)) {
            return Integer.parseInt(propertyValue);
        } else {
            return -1;
        }
    }

}
