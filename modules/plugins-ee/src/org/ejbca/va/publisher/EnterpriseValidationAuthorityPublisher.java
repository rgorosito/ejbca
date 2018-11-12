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
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.Extension;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.certificate.Base64CertData;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateData;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.core.model.ca.publisher.CustomPublisherProperty;
import org.ejbca.core.model.ca.publisher.CustomPublisherUiBase;
import org.ejbca.core.model.ca.publisher.CustomPublisherUiSupport;
import org.ejbca.core.model.ca.publisher.PublisherConnectionException;
import org.ejbca.core.model.ca.publisher.PublisherException;
import org.ejbca.util.JDBCUtil;
import org.ejbca.util.JDBCUtil.Preparer;

/**
 * Publisher writing certificates to an external Database, used by external OCSP responder.
 * 
 * Based on the previous non-proprietary org.ejbca.core.model.ca.publisher.ValidationAuthorityPublisher
 * 
 * @version $Id$
 *
 */
public class EnterpriseValidationAuthorityPublisher extends CustomPublisherUiBase implements CustomPublisherUiSupport  {

    private static final long serialVersionUID = -6093639031082437287L;
    private static final Logger log = Logger.getLogger(EnterpriseValidationAuthorityPublisher.class);
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();
 
    public static final String PROPERTYKEY_DATASOURCE = "dataSource";
    @Deprecated // This is a legacy variable used in EJBCA 3.x. Note that this might still exist in upgraded publishers.
    public static final String PROPERTYKEY_STORECERT = "storeCert";
    public static final String PROPERTYKEY_STORECRL = "storeCRL";
    public static final String PROPERTYKEY_ONLYREVOKED = "onlyPublishRevoked";
    public static final String PROPERTYKEY_DONTSTORECERTIFICATEMETADATA = "dontStoreCertificateMetadata";
    // For non-nullable fields while not storing sensitive certficicate meta data
    public static final String HIDDEN_VALUE = "null";
    
    private final static String insertCertificateSQL = "INSERT INTO CertificateData (base64Cert,subjectDN,issuerDN,cAFingerprint,serialNumber,status,type,username,expireDate,revocationDate,revocationReason,tag,certificateProfileId,updateTime,subjectKeyId,fingerprint,rowVersion) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0)";
    private final static String updateCertificateSQL = "UPDATE CertificateData SET base64Cert=?,subjectDN=?,issuerDN=?,cAFingerprint=?,serialNumber=?,status=?,type=?,username=?,expireDate=?,revocationDate=?,revocationReason=?,tag=?,certificateProfileId=?,updateTime=?,subjectKeyId=?,rowVersion=(rowVersion+1) WHERE fingerprint=? AND (NOT status=40 or revocationReason=6)";
    private final static String deleteCertificateSQL = "DELETE FROM CertificateData WHERE fingerprint=?";
    private final static String insertCRLSQL = "INSERT INTO CRLData (base64Crl,cAFingerprint,cRLNumber,deltaCRLIndicator,issuerDN,thisUpdate,nextUpdate,fingerprint,rowVersion) VALUES (?,?,?,?,?,?,?,?,0)";
    private final static String updateCRLSQL = "UPDATE CRLData SET base64Crl=?,cAFingerprint=?,cRLNumber=?,deltaCRLIndicator=?,issuerDN=?,thisUpdate=?,nextUpdate=?,rowVersion=(rowVersion+1) WHERE fingerprint=?";

    private static final String DEFAULT_DATASOURCE = "java:/OcspDS";

    private String dataSource = DEFAULT_DATASOURCE;
    private boolean storeCertificate = true;
    private boolean storeCrl = true;
    private boolean onlyPublishRevoked = false;
    private boolean dontStoreCertificateMetadata = false;

    public EnterpriseValidationAuthorityPublisher() {
        super();
        // Correct these values if needed
        setClassPath(this.getClass().getName());
    }
    
    /**
     * A copy constructor, in order to create a {@link EnterpriseValidationAuthorityPublisher} from the data payload from another publisher. 
     * 
     * @param newData a map containing publisher data.
     */
    public EnterpriseValidationAuthorityPublisher(final BasePublisher publisher) {
        super(publisher);
        // Correct these values if needed
        setClassPath(this.getClass().getName());
    }
    
    @Override
    public boolean isAuthorizedToPublisher(AuthenticationToken authenticationToken) {
        return false;
    }
    
    @Override
    public boolean isFullEntityPublishingSupported() {
        return true;
    }


    @Override
    public void init(final Properties properties) {
        dataSource = properties.getProperty(PROPERTYKEY_DATASOURCE, DEFAULT_DATASOURCE);
        storeCertificate = Boolean.parseBoolean(properties.getProperty(PROPERTYKEY_STORECERT, Boolean.TRUE.toString()));
        storeCrl = Boolean.parseBoolean(properties.getProperty(PROPERTYKEY_STORECRL, Boolean.TRUE.toString()));
        onlyPublishRevoked = Boolean.parseBoolean(properties.getProperty(PROPERTYKEY_ONLYREVOKED, Boolean.FALSE.toString()));
        dontStoreCertificateMetadata = Boolean
                .parseBoolean(properties.getProperty(PROPERTYKEY_DONTSTORECERTIFICATEMETADATA, Boolean.FALSE.toString()));
        setDescription(properties.getProperty(DESCRIPTION, ""));
        addProperty(new CustomPublisherProperty(DESCRIPTION, CustomPublisherProperty.UI_TEXTINPUT, getDescription()));
        addProperty(new CustomPublisherProperty(PROPERTYKEY_DATASOURCE, CustomPublisherProperty.UI_TEXTINPUT, dataSource));
        addProperty(new CustomPublisherProperty(PROPERTYKEY_STORECERT, CustomPublisherProperty.UI_BOOLEAN, Boolean.toString(storeCertificate)));
        addProperty(new CustomPublisherProperty(PROPERTYKEY_ONLYREVOKED, CustomPublisherProperty.UI_BOOLEAN, Boolean.toString(onlyPublishRevoked)));
        addProperty(new CustomPublisherProperty(PROPERTYKEY_STORECRL, CustomPublisherProperty.UI_BOOLEAN, Boolean.toString(storeCrl)));
        addProperty(new CustomPublisherProperty(PROPERTYKEY_DONTSTORECERTIFICATEMETADATA, CustomPublisherProperty.UI_BOOLEAN,
                Boolean.valueOf(dontStoreCertificateMetadata).toString()));
    }

    @Override
    public boolean storeCertificate(final AuthenticationToken authenticationToken, final CertificateData certificateData, final Base64CertData base64CertData) throws PublisherException {
        final String fingerprint = certificateData.getFingerprint(); 
        final String issuerDN = certificateData.getIssuerDN();
        final String subjectDN = certificateData.getSubjectDN();
        final String cAFingerprint = certificateData.getCaFingerprint();
        final int status = certificateData.getStatus();
        final int type = certificateData.getType();
        final String serialNumber = certificateData.getSerialNumber();
        final long expireDate = certificateData.getExpireDate();
        final long revocationDate = certificateData.getRevocationDate();
        final int revocationReason = certificateData.getRevocationReason();
        String base64Cert = certificateData.getBase64Cert();
        final String username = certificateData.getUsername();
        final String tag  = certificateData.getTag();
        final Integer certificateProfileId = certificateData.getCertificateProfileId();
        final Long updateTime = certificateData.getUpdateTime();
        final String subjectKeyId = certificateData.getSubjectKeyId();
        final int rowVersion = certificateData.getRowVersion();
        final String rowProtection = null;  // Publishing of integrity protection is currently not supported 
        // Check if we are using Base64CertData table and take the certificate from there if needed
        if (getStoreCert() && base64Cert==null && CesecoreConfiguration.useBase64CertTable()) {
            base64Cert = base64CertData.getBase64Cert();
        }
        // Send the request to the remote DB
        final StoreCertPreparer prep = new StoreCertPreparer(fingerprint, issuerDN, subjectDN, cAFingerprint, status, type, serialNumber, expireDate,
                revocationDate, revocationReason, base64Cert, username, tag, certificateProfileId, updateTime, subjectKeyId, rowVersion, rowProtection);
        final boolean doOnlyPublishRevoked = getOnlyPublishRevoked();
        try {
            if (doOnlyPublishRevoked) {
                if (status == CertificateConstants.CERT_REVOKED) {
                    newCert(prep); // 
                    return true;
                }
                if (revocationReason == RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL) {
                    deleteCert(prep); // cert unrevoked, delete it from VA DB.
                    return true;
                }
                if (log.isDebugEnabled()) {
                    log.debug("Not publishing certificate with status " + status + ", type " + type
                            + " to external VA, we only publish revoked certificates.");
                }
                return true; // do nothing if new cert.
            }
            if (status == CertificateConstants.CERT_REVOKED) {
                updateCert(prep);
                return true;
            }
            newCert(prep);
            return true;
        } catch (Exception e) {          
            final String lmsg = intres.getLocalizedMessage("publisher.errorvapubl", getDataSource(), prep.getInfoString());
            log.error(lmsg, e);
            final PublisherException pe = new PublisherException(lmsg);
            pe.initCause(e);
            throw pe;            
        }
    }

    @Override
    public boolean storeCertificate(AuthenticationToken admin, Certificate incert, String username, String password, String userDN, String cafp,
            int status, int type, long revocationDate, int revocationReason, String tag, int certificateProfileId, long lastUpdate,
            ExtendedInformation extendedinformation) throws PublisherException {
        throw new UnsupportedOperationException("Legacy storeCertificate method should never have been invoked for this publisher.");
    }

    @Override
    public boolean storeCRL(AuthenticationToken admin, byte[] incrl, String cafp, int number, String userDN) throws PublisherException {
        if (!getStoreCRL()) {
            if (log.isDebugEnabled()) {
                log.debug("No CRL published. The VA publisher is not configured to do it.");
            }
            return true;
        }
        final Preparer prep = new StoreCRLPreparer(incrl, cafp, number, userDN);
        try {
            JDBCUtil.execute(insertCRLSQL, prep, getDataSource());
        } catch (SQLException e) {
            if (log.isDebugEnabled()) {
                final String msg = intres.getLocalizedMessage("publisher.entryexists", e.getMessage());
                log.debug(msg, e);
            }
            try {
                JDBCUtil.execute(updateCRLSQL, prep, getDataSource());
            } catch (Exception ue) {
                final String lmsg = intres.getLocalizedMessage("publisher.errorvapubl", getDataSource(), prep.getInfoString());
                log.error(lmsg, ue);
                final PublisherException pe = new PublisherException(lmsg);
                pe.initCause(ue);
                throw pe;                       
            }
        } catch (Exception e) {
            final String lmsg = intres.getLocalizedMessage("publisher.errorvapubl", getDataSource(), prep.getInfoString());
            log.error(lmsg, e);
            final PublisherException pe = new PublisherException(lmsg);
            pe.initCause(e);
            throw pe;       
        }
        return true;
    }

    @Override
    public void testConnection() throws PublisherConnectionException {
        try {
            JDBCUtil.execute("select 1 from CertificateData where fingerprint='XX'", new DoNothingPreparer(), getDataSource());
        } catch (Exception e) {
            log.error("Connection test failed: ", e);
            final PublisherConnectionException pce = new PublisherConnectionException("Connection in init failed: " + e.getMessage());
            pce.initCause(e);
            throw pce;
        }
    }
    
    /** @return Should the certificate be published */
    /*package*/ boolean getStoreCert() {
        return storeCertificate;
    }
    
    /** @return Should the CRL be published. */
    /*package*/ boolean getStoreCRL() {
        return storeCrl;
    }
    
    private void updateCert(StoreCertPreparer prep) throws Exception {
        // If this is a revocation we assume that the certificate already exists in the database. In that case we will try an update first and if that fails an insert.
        if (JDBCUtil.execute(updateCertificateSQL, prep, getDataSource()) == 1) {
            return;
        }
        try {
            // If this is a revocation we tried an update below, if that failed we have to do an insert here
            JDBCUtil.execute(insertCertificateSQL, prep, getDataSource());
            // No exception thrown, so this worked
        } catch (SQLException e) {
            // No rows updated. Could occur in async replicated clustered environments in attempt to overwrite status of a permanently revoked certificate.
            log.info("Did not update published certificate\n" + prep.getInfoString() + ". Certificate might already be permanently revoked.");
            return;
        }
    }
    
    /** @return Should only revoked certificates be published? */
    /*package*/ boolean getOnlyPublishRevoked() {
        return onlyPublishRevoked;
    }

    private void newCert(StoreCertPreparer prep) throws Exception {
        try {
            JDBCUtil.execute(insertCertificateSQL, prep, getDataSource());
            // No exception throws, so this worked
        } catch (SQLException e) {
            if (log.isDebugEnabled()) {
                log.debug(intres.getLocalizedMessage("publisher.entryexists", e.getMessage()));
            }
            int updateCount = JDBCUtil.execute(updateCertificateSQL, prep, getDataSource());
            if (updateCount == 1) {
                return; // We updated exactly one row, which is what we expect
            } else if (updateCount == 0) {
                // No rows updated. Could occur in async replicated clustered environments in attempt to overwrite status of a permanently revoked certificate.
                log.info("Did not update published certificate\n" + prep.getInfoString() + ". Certificate might already be permanently revoked.");
                return;
            }
            throw e; // better throw insert exception if this fallback fails.
        }
    }
    
    private void deleteCert(StoreCertPreparer prep) throws Exception {
        prep.isDelete = true;
        JDBCUtil.execute(deleteCertificateSQL, prep, getDataSource());
    }

    
    /** @return The value of the property data source */
    /*package*/ String getDataSource() {
        return dataSource;
    }
    
    private class DoNothingPreparer implements Preparer {
        @Override
        public void prepare(PreparedStatement ps) {
            // do nothing
        }

        @Override
        public String getInfoString() {
            return null;
        }
    }
    
    @Override
    public boolean willPublishCertificate(int status, int revocationReason) {
        if (getOnlyPublishRevoked()) {
            // If we should only publish revoked certificates and
            // - status is not revoked
            // - revocation reason is not REVOCATION_REASON_REMOVEFROMCRL even if status is active
            // Then we will not publish the certificate, in all other cases we will
            if ((status != CertificateConstants.CERT_REVOKED) && (revocationReason != RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL)) {
                if (log.isDebugEnabled()) {
                    log.debug("Will not publish certificate. Status: " + status + ", revocationReason: " + revocationReason);
                }
                return false;
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Will publish certificate. Status: " + status + ", revocationReason: " + revocationReason);
        }
        return true;
    }

    private class StoreCertPreparer implements Preparer {
        private final String fingerprint; 
        private final String issuerDN;
        private final String subjectDN;
        private final String cAFingerprint;
        private final int status;
        private final int type;
        private final String serialNumber;
        private final long expireDate;
        private final long revocationDate;
        private final int revocationReason;
        private String base64Cert;
        private final String username;
        private final String tag;
        private final Integer certificateProfileId;
        private final Long updateTime;
        private final String subjectKeyId;
        //private final int rowVersion = 0;       // Publishing of this is currently not supported
        //private String rowProtection = null;    // Publishing of this is currently not supported
        boolean isDelete = false;

        StoreCertPreparer(String fingerprint, String issuerDN, String subjectDN, String cAFingerprint, int status, int type, String serialNumber,
                long expireDate, long revocationDate, int revocationReason, String base64Cert, String username, String tag, Integer certificateProfileId,
                Long updateTime, final String subjectKeyId, int rowVersion, String rowProtection) {
            super();
            this.fingerprint = fingerprint;
            this.issuerDN = issuerDN;
            this.subjectDN = subjectDN;
            this.cAFingerprint = cAFingerprint;
            this.status = status;
            this.type = type;
            this.serialNumber = serialNumber;
            this.expireDate = expireDate;
            this.revocationDate = revocationDate;
            this.revocationReason = revocationReason;
            this.base64Cert = base64Cert;
            this.username = username;
            this.tag = tag;
            this.certificateProfileId = certificateProfileId;
            this.updateTime = updateTime;
            this.subjectKeyId = subjectKeyId;
        }

        @Override
        public void prepare(PreparedStatement ps) throws Exception {
            if (this.isDelete) {
                prepareDelete(ps);
            } else {
                prepareNewUpdate(ps);
            }
        }

        private void prepareDelete(PreparedStatement ps) throws Exception {
            ps.setString(1, fingerprint);
        }

        private void prepareNewUpdate(PreparedStatement ps) throws Exception {
            // We can select to publish the whole certificate, or not to.
            // There are good reasons not to publish the whole certificate. It is large, thus making it a bit of heavy insert and it may
            // contain sensitive information.
            // On the other hand some OCSP Extension plug-ins may not work without the certificate.
            // A regular OCSP responder works fine without the certificate.
            final String base64Cert;
            if (getStoreCert()) {
                base64Cert = this.base64Cert;
            } else {
                base64Cert = null;
            }
            final boolean isCaCert = CertTools.isCA(CertTools.getCertfromByteArray(Base64.decode(this.base64Cert.getBytes()), X509Certificate.class));
            final boolean isOcspCert = CertTools.isOCSPCert(CertTools.getCertfromByteArray(Base64.decode(this.base64Cert.getBytes()), X509Certificate.class));
            // Don't store user sensitive certificate data
            final boolean limitMetaData = dontStoreCertificateMetadata && !isCaCert && !isOcspCert;
            ps.setString(1, limitMetaData ? null : base64Cert);
            ps.setString(2, limitMetaData ? HIDDEN_VALUE : subjectDN);
            ps.setString(3, issuerDN);
            ps.setString(4, cAFingerprint);
            ps.setString(5, serialNumber);
            ps.setInt(6, status);
            ps.setInt(7, type);
            ps.setString(8, limitMetaData ? null : username);
            ps.setLong(9, expireDate);
            ps.setLong(10, revocationDate);
            ps.setInt(11, revocationReason);
            ps.setString(12, limitMetaData ? null: tag);
            ps.setInt(13, certificateProfileId);
            ps.setLong(14, updateTime);
            ps.setString(15, limitMetaData ? null : subjectKeyId);
            ps.setString(16, fingerprint);
        }

        @Override
        public String getInfoString() {
            return "Store:, Username: " + this.username + ", Issuer:" + issuerDN + ", Serno: " + serialNumber + ", Subject: " + subjectDN;
        }
    }
    
    private class StoreCRLPreparer implements Preparer {
        private final String base64Crl;
        private final String cAFingerprint;
        private final int cRLNumber;
        private final int deltaCRLIndicator;
        private final String issuerDN;
        private final String fingerprint;
        private final long thisUpdate;
        private final long nextUpdate;

        StoreCRLPreparer(byte[] incrl, String cafp, int number, String userDN) throws PublisherException {
            super();
            final X509CRL crl;
            try {
                crl = CertTools.getCRLfromByteArray(incrl);
                // Is it a delta CRL?
                this.deltaCRLIndicator = crl.getExtensionValue(Extension.deltaCRLIndicator.getId()) != null ? 1 : -1;
                this.issuerDN = userDN;
                this.cRLNumber = number;
                this.cAFingerprint = cafp;
                this.base64Crl = new String(Base64.encode(incrl));
                this.fingerprint = CertTools.getFingerprintAsString(incrl);
                this.thisUpdate = crl.getThisUpdate().getTime();
                this.nextUpdate = crl.getNextUpdate().getTime();
                if (log.isDebugEnabled()) {
                    log.debug("Publishing CRL with fingerprint " + this.fingerprint + ", number " + number + " to external CRL store for the CA "
                            + this.issuerDN + (this.deltaCRLIndicator > 0 ? ". It is a delta CRL." : "."));
                }
            } catch (Exception e) {
                String msg = intres.getLocalizedMessage("publisher.errorldapdecode", "CRL");
                log.error(msg, e);
                throw new PublisherException(msg);
            }
        }

        @Override
        public void prepare(PreparedStatement ps) throws Exception {
            ps.setString(1, this.base64Crl);
            ps.setString(2, this.cAFingerprint);
            ps.setInt(3, this.cRLNumber);
            ps.setInt(4, this.deltaCRLIndicator);
            ps.setString(5, this.issuerDN);
            ps.setLong(6, this.thisUpdate);
            ps.setLong(7, this.nextUpdate);
            ps.setString(8, this.fingerprint);
        }

        @Override
        public String getInfoString() {
            return "Store CRL:, Issuer:" + this.issuerDN + ", Number: " + this.cRLNumber + ", Is delta: " + (this.deltaCRLIndicator > 0);
        }
    }
    
    @Override
    public boolean isReadOnly() {
        return false;
    }


}
