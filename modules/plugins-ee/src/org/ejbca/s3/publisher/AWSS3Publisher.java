/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.s3.publisher;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.util.CertTools;
import org.cesecore.util.ExternalProcessException;
import org.cesecore.util.ExternalProcessTools;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.ca.publisher.CustomPublisherContainer;
import org.ejbca.core.model.ca.publisher.CustomPublisherProperty;
import org.ejbca.core.model.ca.publisher.CustomPublisherUiSupport;
import org.ejbca.core.model.ca.publisher.ICustomPublisher;
import org.ejbca.core.model.ca.publisher.PublisherConnectionException;
import org.ejbca.core.model.ca.publisher.PublisherException;

/**
 * This class is used for publishing certificates and CRLs to an AWS S3 Bucket using the AWS CLI. 
 * Certificates and CRLs can be published to different buckets.
 * Properties available:
 * - s3.crl.bucket.name: S3 bucket name
 * - s3.cert.bucket.name: S3 bucket name
 * - s3.crl.key.prefix: An optional file name prefix. The prefix will be created when a certificate file is copied to the bucket and may have multiple 
 *   levels separated by "/" (for example, mykeyprefixa/mykeyprefixb). Validation is in place for the Safe Characters specified in the AWS documentation
 * - s3.cert.key.prefix: as for CRLs
 * - s3.crl.file.format: 0=DER or 1=PEM
 * - s3.cert.file.format: as for CRL
 * - s3.crl.file.name.format: 0=CA CN/SN/O, 1=CA SHA-1 Fingerprint
 *   (the CN part of the issuer DN, or DN SERIALNUMBER if CN does not exist, or O if neither of the previous exist)
 * - s3.cert.file.name.format: 0=Serial number, 1=SHA-1 Fingerprint, 2=SHA-256 Fingerprint
 * - s3.cert.store.separate.path: If set to true stores active certs in "active" path and revoked certs in "revoked" path. 
 *   When an active cert is stored, removes cert from "revoked" path. When a revoked cert is stored, removes cert from "active" path.
 *
 * @version $Id$
 */
public class AWSS3Publisher  extends CustomPublisherContainer implements ICustomPublisher, CustomPublisherUiSupport, Serializable {

    private static final long serialVersionUID = 1L;

    private static final Logger log = Logger.getLogger(AWSS3Publisher.class);

    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    /** S3 bucket name property */
    public static final String S3_CRL_BUCKET_NAME_PROPERTY_NAME = "s3.crl.bucket.name";

    /** S3 key prefix property */
    public static final String S3_CRL_KEY_PREFIX_PROPERTY_NAME = "s3.crl.key.prefix";

    /** S3 bucket name property */
    public static final String S3_CERT_BUCKET_NAME_PROPERTY_NAME = "s3.cert.bucket.name";

    /** S3 key prefix property */
    public static final String S3_CERT_KEY_PREFIX_PROPERTY_NAME = "s3.cert.key.prefix";

    /** S3 CRL file format: DER/PEM */
    public static final String S3_CRL_FILE_FORMAT_PROPERTY_NAME = "s3.crl.file.format";

    /** S3 certificate file format: DER/PEM */
    public static final String S3_CERT_FILE_FORMAT_PROPERTY_NAME = "s3.cert.file.format";

    /** S3 store active and revoked certificates in separate paths */
    public static final String S3_CERT_STORE_SEPARATE_PATH_PROPERTY_NAME = "s3.cert.store.separate.path";

    /** S3 certificate file name Serial No./SHA-1 Fingerprint/SHA-256 Fingerprint */
    public static final String S3_CERT_FILE_NAME_FORMAT_PROPERTY_NAME = "s3.cert.file.name.format";

    /** S3 CRL file name CA DN or CA Fingerprint */
    public static final String S3_CRL_FILE_NAME_FORMAT_PROPERTY_NAME = "s3.crl.file.name.format";


    /** Input values **/  
    private String s3CrlBucketNameStr = "";
    private String s3CrlKeyPrefixStr = "";
    private String s3CertBucketNameStr = "";
    private String s3CertKeyPrefixStr = "";
    private int s3CrlFormatIdx = 0;
    private int s3CertFormatIdx = 0;
    private boolean s3CertStoreSeparatePath = true;
    private int s3CertFileNameFormatIdx = 0;
    private int s3CrlFileNameFormatIdx = 0;

    /** Literal for exit code label / prefix. */
    public static final String EXIT_CODE_PREFIX = "Exit code: ";

    /** Literal for STDOUT label to log the external out streams . */
    public static final String STDOUT_PREFIX = "STDOUT: ";

    /** Literal for ERROUT label to log the external out streams . */
    public static final String ERROUT_PREFIX = "ERROUT: ";

    private final Map<String, CustomPublisherProperty> properties = new LinkedHashMap<>();

    /**
     * Creates a new empty instance of AWSS3Publisher, init should be called after contruction
     */
    public AWSS3Publisher() {}

    /**
     * Load used properties.
     * 
     * @param properties The properties to load.
     * 
     * @see org.ejbca.core.model.ca.publisher.ICustomPublisher#init(java.util.Properties)
     */
    @Override
    public void init(Properties properties) {
        if (log.isTraceEnabled()) {
            log.trace(">AWSS3Publisher init");
        }

        //get saved property values
        s3CrlFormatIdx = getIntProperty(properties, S3_CRL_FILE_FORMAT_PROPERTY_NAME);
        s3CertFormatIdx = getIntProperty(properties, S3_CERT_FILE_FORMAT_PROPERTY_NAME);
        s3CertFileNameFormatIdx = getIntProperty(properties, S3_CERT_FILE_NAME_FORMAT_PROPERTY_NAME);
        s3CrlFileNameFormatIdx = getIntProperty(properties, S3_CRL_FILE_NAME_FORMAT_PROPERTY_NAME);
        s3CrlBucketNameStr = getProperty(properties, S3_CRL_BUCKET_NAME_PROPERTY_NAME);
        s3CrlKeyPrefixStr =  getProperty(properties, S3_CRL_KEY_PREFIX_PROPERTY_NAME);
        s3CertBucketNameStr = getProperty(properties, S3_CERT_BUCKET_NAME_PROPERTY_NAME);
        s3CertKeyPrefixStr =  getProperty(properties, S3_CERT_KEY_PREFIX_PROPERTY_NAME);
        s3CertStoreSeparatePath = getBooleanProperty(properties, S3_CERT_STORE_SEPARATE_PATH_PROPERTY_NAME);

        //set property UI fields
        this.properties.put(S3_CRL_BUCKET_NAME_PROPERTY_NAME,
                new CustomPublisherProperty(S3_CRL_BUCKET_NAME_PROPERTY_NAME, CustomPublisherProperty.UI_TEXTINPUT, s3CrlBucketNameStr));
        this.properties.put(S3_CRL_KEY_PREFIX_PROPERTY_NAME,
                new CustomPublisherProperty(S3_CRL_KEY_PREFIX_PROPERTY_NAME, CustomPublisherProperty.UI_TEXTINPUT, s3CrlKeyPrefixStr));
        this.properties.put(S3_CRL_FILE_FORMAT_PROPERTY_NAME, new CustomPublisherProperty(S3_CRL_FILE_FORMAT_PROPERTY_NAME, CustomPublisherProperty.UI_SELECTONE, null,
                null, Integer.valueOf(s3CrlFormatIdx).toString()));
        this.properties.put(S3_CRL_FILE_NAME_FORMAT_PROPERTY_NAME, new CustomPublisherProperty(S3_CRL_FILE_NAME_FORMAT_PROPERTY_NAME, CustomPublisherProperty.UI_SELECTONE, null,
                null, Integer.valueOf(s3CrlFileNameFormatIdx).toString()));
        this.properties.put(S3_CERT_BUCKET_NAME_PROPERTY_NAME,
                new CustomPublisherProperty(S3_CERT_BUCKET_NAME_PROPERTY_NAME, CustomPublisherProperty.UI_TEXTINPUT, s3CertBucketNameStr));
        this.properties.put(S3_CERT_KEY_PREFIX_PROPERTY_NAME,
                new CustomPublisherProperty(S3_CERT_KEY_PREFIX_PROPERTY_NAME, CustomPublisherProperty.UI_TEXTINPUT, s3CertKeyPrefixStr));
        this.properties.put(S3_CERT_FILE_FORMAT_PROPERTY_NAME, new CustomPublisherProperty(S3_CERT_FILE_FORMAT_PROPERTY_NAME, CustomPublisherProperty.UI_SELECTONE, null,
                null, Integer.valueOf(s3CertFormatIdx).toString()));
        this.properties.put(S3_CERT_STORE_SEPARATE_PATH_PROPERTY_NAME, new CustomPublisherProperty(S3_CERT_STORE_SEPARATE_PATH_PROPERTY_NAME,
                CustomPublisherProperty.UI_BOOLEAN, Boolean.valueOf(s3CertStoreSeparatePath).toString()));
        this.properties.put(S3_CERT_FILE_NAME_FORMAT_PROPERTY_NAME, new CustomPublisherProperty(S3_CERT_FILE_NAME_FORMAT_PROPERTY_NAME, CustomPublisherProperty.UI_SELECTONE, null,
                null, Integer.valueOf(s3CertFileNameFormatIdx).toString()));


        if (log.isTraceEnabled()) {
            log.trace("<AWSS3Publisher init");
        }
    }


    @Override
    public List<CustomPublisherProperty> getCustomUiPropertyList(AuthenticationToken authenticationToken) {
        final List<CustomPublisherProperty> customProperties = new ArrayList<>();
        final List<String> availableFormatIds = new ArrayList<>();
        final List<String> availableFormatNames = new ArrayList<>();

        final List<String> availableCertNameFormatIds = new ArrayList<>();
        final List<String> availableCertNameFormatNames = new ArrayList<>();
        final List<String> availableCrlNameFormatIds = new ArrayList<>();
        final List<String> availableCrlNameFormatNames = new ArrayList<>();

        // Selection field values and labels
        availableFormatIds.add("0");
        availableFormatNames.add("DER");

        availableFormatIds.add("1");
        availableFormatNames.add("PEM");

        availableCertNameFormatIds.add("0");
        availableCertNameFormatNames.add("Serial Number");

        availableCertNameFormatIds.add("1");
        availableCertNameFormatNames.add("SHA-1 Fingerprint");

        availableCertNameFormatIds.add("2");
        availableCertNameFormatNames.add("SHA-256 Fingerprint");

        availableCrlNameFormatIds.add("0");
        availableCrlNameFormatNames.add("CA CN/SN/O");

        availableCrlNameFormatIds.add("1");
        availableCrlNameFormatNames.add("CA SHA-1 Fingerprint");

        for (final String key : properties.keySet()) {
            switch (key) {
            case S3_CRL_FILE_FORMAT_PROPERTY_NAME:
                customProperties.add(new CustomPublisherProperty(S3_CRL_FILE_FORMAT_PROPERTY_NAME, CustomPublisherProperty.UI_SELECTONE, availableFormatIds, availableFormatNames,
                        Integer.valueOf(s3CrlFormatIdx).toString()));
                break;
            case S3_CERT_FILE_FORMAT_PROPERTY_NAME:
                customProperties.add(new CustomPublisherProperty(S3_CERT_FILE_FORMAT_PROPERTY_NAME, CustomPublisherProperty.UI_SELECTONE, availableFormatIds, availableFormatNames,
                        Integer.valueOf(s3CertFormatIdx).toString()));
                break;
            case S3_CERT_FILE_NAME_FORMAT_PROPERTY_NAME:
                customProperties.add(new CustomPublisherProperty(S3_CERT_FILE_NAME_FORMAT_PROPERTY_NAME, CustomPublisherProperty.UI_SELECTONE, availableCertNameFormatIds, availableCertNameFormatNames,
                        Integer.valueOf(s3CertFileNameFormatIdx).toString()));
                break;
            case S3_CRL_FILE_NAME_FORMAT_PROPERTY_NAME:
                customProperties.add(new CustomPublisherProperty(S3_CRL_FILE_NAME_FORMAT_PROPERTY_NAME, CustomPublisherProperty.UI_SELECTONE, availableCrlNameFormatIds, availableCrlNameFormatNames,
                        Integer.valueOf(s3CrlFileNameFormatIdx).toString()));
                break;
            default:
                customProperties.add(properties.get(key));
                break;
            }
        }     
        return customProperties;
    }

    @Override
    public List<String> getCustomUiPropertyNames() {
        return new ArrayList<>(properties.keySet());
    }

    @Override
    public int getPropertyType(String label) {
        final CustomPublisherProperty property = properties.get(label);
        if (property == null) {
            return -1;
        } else {
            return property.getType();
        }
    }

    private int getIntProperty(Properties properties, String propertyName) {
        final String property = getProperty(properties, propertyName);
        if (StringUtils.isEmpty(property)) {
            return -1;
        } else {
            return Integer.valueOf(property);
        }
    }

    private boolean getBooleanProperty(Properties properties, String propertyName) {
        final String property = getProperty(properties, propertyName);
        // Default to true - store active and revoked certs in separate paths (active/revoked)
        if ((property.equals("") && propertyName.equals(S3_CERT_STORE_SEPARATE_PATH_PROPERTY_NAME)) || property.equalsIgnoreCase("true")) {
            return true;
        } else {
            return false;
        }
    }

    private String getProperty(Properties properties, String propertyName) {
        final String property = properties.getProperty(propertyName);
        if (property == null) {
            return "";
        } else {
            return property;
        }
    }

    @Override
    public boolean storeCertificate(AuthenticationToken admin, Certificate incert, String username, String password, String userDN, String cafp, int status, int type, long revocationDate, int revocationReason, String tag, int certificateProfileId, long lastUpdate, ExtendedInformation extendedinformation) throws PublisherException {
        if (log.isTraceEnabled()) {
            log.trace(">AWSS3Publisher storeCertificate, Storing Certificate for user: " + username);
        }

        if ((status == CertificateConstants.CERT_REVOKED) || (status == CertificateConstants.CERT_ACTIVE)) {
            // Don't publish non-active certificates
            byte[] byteArrCert;
            try {
                byteArrCert = incert.getEncoded();
                if (s3CertFormatIdx == 1) {
                    String certPEM = CertTools.getPemFromCertificate(incert);
                    byteArrCert = certPEM.getBytes();
                }
            } catch (CertificateEncodingException e) {
                String msg = e.getMessage();
                log.error(msg);
                throw new PublisherException(msg, e);
            }

            final String issuerDN = CertTools.getIssuerDN(incert);
            // Verify initialization
            if (s3CertBucketNameStr == null || s3CertBucketNameStr.equals("")) {
                final String msg = intres.getLocalizedMessage("publisher.errormissingproperty", S3_CERT_BUCKET_NAME_PROPERTY_NAME);
                log.error(msg);
                throw new PublisherException(msg);
            }

            final StringBuilder sbRebuildKeyPrefix = new StringBuilder();
            try {
                // Validate S3 Bucket Name for certificates
                validateS3BucketName(s3CertBucketNameStr, "certificate");
                // Validate key prefix
                validateS3KeyPrefix(s3CertKeyPrefixStr, sbRebuildKeyPrefix, "certificate", 911);
            } catch (PublisherException pe) {
                throw new PublisherException(pe.getMessage());
            }

            final List<String> additionalArguments = new ArrayList<>();
            // Construct S3 URI
            StringBuilder sbS3URI = new StringBuilder();
            sbS3URI.append("s3://");
            sbS3URI.append(s3CertBucketNameStr);
            sbS3URI.append("/");

            // Append key prefix if not empty
            s3CertKeyPrefixStr = sbRebuildKeyPrefix.toString();
            if (s3CertKeyPrefixStr != null && !s3CertKeyPrefixStr.equals("")) {
                sbS3URI.append(s3CertKeyPrefixStr);
            }

            // Append Issuer CA CN (spaces truncated)
            sbS3URI.append(getBaseFileName(issuerDN));
            sbS3URI.append("/");

            // Set filename as Serial Number, SHA-1 Fingerprint, or SHA-256 Fingerprint
            final String strCertFileName;
            if (s3CertFileNameFormatIdx == 0) {
                //Serial Number
                strCertFileName = CertTools.getSerialNumberAsString(incert);
            } else if (s3CertFileNameFormatIdx == 1) {
                //SHA-1 Fingerprint
                strCertFileName = CertTools.getFingerprintAsString(incert);
            } else {
                //SHA-256 Fingerprint
                strCertFileName = CertTools.getSHA256FingerprintAsString(byteArrCert);
            }

            final StringBuilder sbS3RemoveURI;
            // Store active certs in "active" path and revoked certs in "revoked" path.
            // When an active cert is stored, remove cert from "revoked" path.
            // When a revoked cert is stored, removed cert from "active" path.
            if (s3CertStoreSeparatePath) {
                if (status == CertificateConstants.CERT_ACTIVE) {
                    sbS3URI.append("active/");
                    sbS3URI.append(strCertFileName);
                    sbS3RemoveURI = new StringBuilder(sbS3URI);
                    sbS3RemoveURI.append("revoked/");
                    sbS3RemoveURI.append(strCertFileName);
                } else { //CERT_REVOKED
                    sbS3RemoveURI = new StringBuilder(sbS3URI);
                    sbS3RemoveURI.append("active/");
                    sbS3RemoveURI.append(strCertFileName);
                    sbS3URI.append("revoked/");
                    sbS3URI.append(strCertFileName);
                }

                final List<String> additionalArgumentsRemove = new ArrayList<>();
                additionalArgumentsRemove.add(sbS3RemoveURI.toString());

                final String cmd = "aws s3 rm";
                final String strRemoveFailMsg = "Error deleting file from S3 Bucket.";

                // Throws PublisherException. No need to catch exception.
                launchExternalCommandNoTempFile(cmd, true, true, true, true, additionalArgumentsRemove, strRemoveFailMsg);
            } else {
                // Do not use separate paths for active and revoked certificates
                // Replace certificate if it already exists
                sbS3URI.append(strCertFileName);
            }

            additionalArguments.add(sbS3URI.toString());
            try {
                ExternalProcessTools.launchExternalCommand("aws s3 cp", byteArrCert, true, true, additionalArguments, strCertFileName);
            } catch (ExternalProcessException e) {
                throw new PublisherException(e.getMessage());
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<AWSS3Publisher storeCertificate");
        }
        return true;
    }

    @Override
    public boolean storeCRL(AuthenticationToken admin, byte[] incrl, String cafp, int number, String userDN) throws PublisherException {
        if (log.isTraceEnabled()) {
            log.trace(">AWSS3Publisher storeCRL, Storing CRL");
        }

        // Verify initialization
        if (s3CrlBucketNameStr == null || s3CrlBucketNameStr.equals("")) {
            final String msg = intres.getLocalizedMessage("publisher.errormissingproperty", S3_CRL_BUCKET_NAME_PROPERTY_NAME);
            log.error(msg);
            throw new PublisherException(msg);
        }


        StringBuilder sbRebuildKeyPrefix = new StringBuilder();
        try {
            // Validate S3 Bucket Name for certificates
            validateS3BucketName(s3CrlBucketNameStr, "CRL");
            // Validate key prefix
            // Issuer CA CN - max 64 chars
            // "revoked" - 7 chars
            // <Issuer CA CN>.crl = 68 chars/bytes (no special chars)
            // allow 1024 - 68 = 956 bytes max for key prefix
            validateS3KeyPrefix(s3CrlKeyPrefixStr, sbRebuildKeyPrefix, "CRL", 956);
        } catch (PublisherException pe) {
            throw new PublisherException(pe.getMessage());
        }

        final List<String> additionalArguments = new ArrayList<>();
        final StringBuilder sbTempFileName = new StringBuilder();
        final String filename;
        
        try {
            final X509CRL crl = CertTools.getCRLfromByteArray(incrl);
            String crlDN = crl.getIssuerX500Principal().getName(X500Principal.RFC2253);
            // Get file name from DN
            sbTempFileName.append(getBaseFileName(crlDN));

            if (s3CrlFileNameFormatIdx == 1) {
                filename = cafp;
            } else {
                filename = sbTempFileName.toString();
            }
        } catch (CRLException e) {
            throw new PublisherException(e.getMessage());
        }

        final StringBuilder sbS3URI = new StringBuilder();
        sbS3URI.append("s3://");
        sbS3URI.append(s3CrlBucketNameStr);
        sbS3URI.append("/");

        s3CrlKeyPrefixStr = sbRebuildKeyPrefix.toString();
        if (s3CrlKeyPrefixStr != "") {
            sbS3URI.append(s3CrlKeyPrefixStr);
        }
        sbS3URI.append(filename);
        sbS3URI.append(".crl");
        additionalArguments.add(sbS3URI.toString());
        byte[] byteArrCrl = incrl;
        // Set as DER or PEM depending on format selection
        if (s3CrlFormatIdx == 1) {
            byteArrCrl = CertTools.getPEMFromCrl(incrl);
        }

        try {
            ExternalProcessTools.launchExternalCommand("aws s3 cp", byteArrCrl, true, true, additionalArguments, sbTempFileName.toString());
        } catch (ExternalProcessException e) {
            throw new PublisherException(e.getMessage());
        }

        if (log.isTraceEnabled()) {
            log.trace("<AWSS3Publisher storeCRL");
        }
        return true;
    }

    /**
     * Performs input validation of S3 Bucket Name parameter.
     * Throws PublisherException if name is invalid.
     * 
     * @param strBucketName S3 Bucket Name parameter.
     * @param strCertOrCRL Specifies if validation is for a CRL bucket or a Certificate bucket.
     * @throws PublisherException if the name is invalid
     */
    private void validateS3BucketName(String strBucketName, String strCertOrCRL) throws PublisherException {
        // Validate bucket name
        // between 3 and 63 characters long
        // does not resemble an IP address
        // cannot contain underscores, end with a dash, have consecutive periods, or use dashes adjacent to periods
        final Pattern patValBucketName = Pattern.compile("(?=^.{3,63}$)(?!^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$)(^(([a-z0-9]|[a-z0-9][a-z0-9\\-]*[a-z0-9])\\.)*([a-z0-9]|[a-z0-9][a-z0-9\\-]*[a-z0-9])$)");
        final Matcher matcher = patValBucketName.matcher(strBucketName);
        if (!matcher.matches()) {
            String strProperty = S3_CRL_BUCKET_NAME_PROPERTY_NAME;
            if (strCertOrCRL != null && strCertOrCRL.equals("certificate")) {
                strProperty = S3_CERT_BUCKET_NAME_PROPERTY_NAME;
            }            
            final String msg = intres.getLocalizedMessage("publisher.errorinvalidvalue", strProperty);
            log.error(msg);
            final StringBuilder sbInvalidBucketName = new StringBuilder("The specified ");
            sbInvalidBucketName.append(strCertOrCRL);
            sbInvalidBucketName.append(" bucket name is not valid.");
            throw new PublisherException(sbInvalidBucketName.toString());
        }
    }

    /**
     * Performs input validation of S3 Key Prefix parameter.
     * Throws PublisherException if name is invalid.
     * 
     * @param strKeyPrefix S3 Key Prefix parameter.
     * @param sbRebuildKeyPrefix The key prefix is rebuilt while validating each section delimited by /.
     * @param strCertOrCRL Specifies if validation is for a CRL key prefix or a Certificate key prefix.
     * @param maxlength Maximum length of key prefix.
     * @throws PublisherException if the key prefix is invalid
     */
    private void validateS3KeyPrefix(String strKeyPrefix, StringBuilder sbRebuildKeyPrefix, String strCertOrCRL, int maxlength) throws PublisherException {

        // Amazon accepts object key names up to 1024 bytes long (UTF-8 encoding)
        // Serial no. and Fingerprint are 20 octets (40 chars)
        // Issuer CA CN - max 64 chars
        // "revoked" - 7 chars
        // <Issuer CA CN>/revoked/<Serial No. or Fingerprint> = 113 chars/bytes (no special chars)
        // allow 1024 - 113 = 911 bytes max for key prefix

        final StringBuilder sbInvalidKeyPrefixMsg = new StringBuilder("The specified ");
        sbInvalidKeyPrefixMsg.append(strCertOrCRL);
        sbInvalidKeyPrefixMsg.append(" bucket key prefix is not valid.");

        final StringBuilder sbKeyPrefixExceedsMaxlength = new StringBuilder("The specified ");
        sbKeyPrefixExceedsMaxlength.append(strCertOrCRL);
        sbKeyPrefixExceedsMaxlength.append(" bucket key prefix exceeds maxium length.");

        String strProperty = S3_CRL_KEY_PREFIX_PROPERTY_NAME;
        if (strCertOrCRL != null && strCertOrCRL.equals("certificate")) {
            strProperty = S3_CERT_KEY_PREFIX_PROPERTY_NAME;
        }

        int intPrefixNumBytes = 0;
        try {
            byte[] byteArrS3KeyPrefix = strKeyPrefix.getBytes("UTF-8");
            intPrefixNumBytes = byteArrS3KeyPrefix.length;
        } catch (UnsupportedEncodingException uee) {
            // UTF-8 unsupported. Should never occur
            final String msg = intres.getLocalizedMessage("publisher.errorinvalidvalue", strProperty);
            log.info(msg);
            throw new PublisherException(sbInvalidKeyPrefixMsg.toString());
        }

        if (intPrefixNumBytes > maxlength) {
            final String msg = intres.getLocalizedMessage("publisher.errorinvalidvalue", strProperty);
            log.info(msg);
            throw new PublisherException(sbKeyPrefixExceedsMaxlength.toString());
        }

        // Only allow safe characters defined in Amazon documentation: https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingMetadata.html
        final Pattern patValKeyPrefix = Pattern.compile("[a-zA-Z0-9!\\-_.*')(]+");
        final String[] strArrKeyPrefixes = strKeyPrefix.split("/");

        Matcher keyPrefixMatcher;
        // Split key prefix by / and validate each segment
        for (String strPrefixPart: strArrKeyPrefixes) {
            if (strPrefixPart.equals("")) continue; // Ignore doubled-up and leading slashes
            keyPrefixMatcher = patValKeyPrefix.matcher(strPrefixPart);
            if (!keyPrefixMatcher.matches()) {
                final String msg = intres.getLocalizedMessage("publisher.errorinvalidvalue", strProperty);
                log.info(msg);
                throw new PublisherException(sbInvalidKeyPrefixMsg.toString());
            }
            sbRebuildKeyPrefix.append(strPrefixPart);
            sbRebuildKeyPrefix.append("/");
        }
    }

    @Override
    public void testConnection() throws PublisherConnectionException {
        log.debug("AWSS3Publisher, Testing connection");

        //s3 Certificate bucket and s3 CRL bucket are both blank
        if ((s3CertBucketNameStr == null || s3CertBucketNameStr.equals("")) && (s3CrlBucketNameStr == null || s3CrlBucketNameStr.equals(""))) {
            final String msg = "At least one S3 Bucket Name must be specified.";
            log.info(msg);
            throw new PublisherConnectionException(msg);
        }

        if (s3CertBucketNameStr != null && !s3CertBucketNameStr.equals("")) {
            final StringBuilder sbRebuildKeyPrefix = new StringBuilder();
            try {
                // Validate Bucket Name
                validateS3BucketName(s3CertBucketNameStr, "certificate");
                // Validate key prefix
                validateS3KeyPrefix(s3CertKeyPrefixStr, sbRebuildKeyPrefix, "certificate", 911);
            } catch (PublisherException pe) {
                throw new PublisherConnectionException(pe.getMessage());
            }

            final String cmd = "aws s3api head-bucket --bucket";
            final String strConnectionFailMsg = "Could not access the specified certificate bucket.";
            final List<String> arguments = new ArrayList<>();
            arguments.add(s3CertBucketNameStr);
            try {
                launchExternalCommandNoTempFile(cmd, true, true, true, true, arguments, strConnectionFailMsg);
            } catch (PublisherException pe) {
                throw new PublisherConnectionException(pe.getMessage());
            }
        }

        //Validate CRL bucket
        if (s3CrlBucketNameStr != null && !s3CrlBucketNameStr.equals("")) {

            // Validate bucket name
            // Issuer CA CN - max 64 chars
            // "revoked" - 7 chars
            // <Issuer CA CN>.crl = 68 chars/bytes (no special chars)
            // allow 1024 - 68 = 956 bytes max for key prefix

            final StringBuilder sbRebuildKeyPrefix = new StringBuilder();
            try {
                // Validate S3 Bucket Name
                validateS3BucketName(s3CrlBucketNameStr, "CRL");
                // Validate key prefix
                validateS3KeyPrefix(s3CrlKeyPrefixStr, sbRebuildKeyPrefix, "CRL", 956);
            } catch (PublisherException pe) {
                throw new PublisherConnectionException(pe.getMessage());
            }

            final String cmd = "aws s3api head-bucket --bucket";
            final String strConnectionFailMsg = "Could not access the specified CRL bucket.";
            final List<String> arguments = new ArrayList<>();
            arguments.add(s3CrlBucketNameStr);
            try {
                launchExternalCommandNoTempFile(cmd, true, true, true, true, arguments, strConnectionFailMsg);
            } catch (PublisherException pe) {
                throw new PublisherConnectionException(pe.getMessage());
            }
        }
    }

    /**
     * Executes an external command. The function will, depending on its parameters, fail if output to
     * standard error from the command was detected or the command returns with an non-zero exit code.
     * 
     * @param cmd The command to run.
     * @param failOnCode Determines if the method should fail on a non-zero exit code.
     * @param failOnOutput Determines if the method should fail on output to standard error.
     * @param logStdOut if the scripts STDOUT should be logged as info.
     * @param logErrOut if the scripts ERROUT should be logged as info.
     * @param arguments Added to the command
     * @param strFailMsg Message returned in exception if command fails.
     * @throws PublisherException if the external process fails.
     */
    private static final List<String> launchExternalCommandNoTempFile(final String cmd, final boolean failOnCode, final boolean failOnOutput,
            final boolean logStdOut, final boolean logErrOut, final List<String> arguments, String strFailMsg) throws PublisherException {

        int exitStatus = -1;

        final List<String> result = new ArrayList<String>();
        // Launch external process.
        final List<String> cmdTokens = Arrays.asList(cmd.split("\\s"));
        final List<String> cmdArray = new ArrayList<String>();
        cmdArray.addAll(cmdTokens);
        cmdArray.addAll(arguments);


        try {
            final Process externalProcess = Runtime.getRuntime().exec(cmdArray.toArray(new String[] {}), null, null);
            externalProcess.getOutputStream().close(); // prevent process from trying to wait for user input (e.g. prompt for overwrite, or similar)
            final BufferedReader stdError = new BufferedReader(new InputStreamReader(externalProcess.getErrorStream()));
            final BufferedReader stdOut = new BufferedReader(new InputStreamReader(externalProcess.getInputStream()));
            String line = null;
            while ((line = stdOut.readLine()) != null) { // NOPMD: Required under win32 to avoid lock
                if (logStdOut) {
                    result.add(STDOUT_PREFIX + line);
                }
            }
            String stdErrorOutput = null;
            // Check error code and the external applications output to STDERR.
            exitStatus = externalProcess.waitFor();
            result.add(0, EXIT_CODE_PREFIX + exitStatus);
            if (((exitStatus != 0) && failOnCode) || (stdError.ready() && failOnOutput)) {
                String errTemp = null;
                while (stdError.ready() && (errTemp = stdError.readLine()) != null) {
                    if (logErrOut) {
                        result.add(ERROUT_PREFIX + errTemp);
                    }
                    if (stdErrorOutput == null) {
                        stdErrorOutput = errTemp;
                    } else {
                        stdErrorOutput += "\n" + errTemp;
                    }
                }
                final StringBuilder sbResult = new StringBuilder();
                for (String resLine: result) {
                    sbResult.append(resLine);
                    sbResult.append("\n");
                }
                String msg = intres.getLocalizedMessage("process.errorexternalapp", cmd);
                if (stdErrorOutput != null) {
                    msg += " - " + stdErrorOutput + sbResult;
                    log.error(msg);
                } 
                throw new PublisherException(strFailMsg);
            }
        } catch (IOException | InterruptedException e) {
            String msg = e.getMessage();
            log.error(msg);
            throw new PublisherException(strFailMsg, e);
        }
        return result;

    }

    @Override
    public boolean willPublishCertificate(int status, int revocationReason) {
        return true;
    }

    @Override
    public boolean isReadOnly() {
        return false;
    }

    /**
     * @param dn
     * @return base filename, without extension, with CN, or SN (if CN is null) or O, with spaces removed so name is compacted.
     */
    private String getBaseFileName(String dn) {
        String dnpart = CertTools.getPartFromDN(dn, "CN");
        if (dnpart == null) {
            dnpart = CertTools.getPartFromDN(dn, "SN");
        }
        if (dnpart == null) {
            dnpart = CertTools.getPartFromDN(dn, "O");
        }
        final String basename = dnpart.replaceAll("\\W", "");
        return basename;
    }
}