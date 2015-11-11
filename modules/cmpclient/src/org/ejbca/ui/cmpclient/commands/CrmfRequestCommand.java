/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.cmpclient.commands;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CertOrEncCert;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.CertifiedKeyPair;
import org.bouncycastle.asn1.cmp.ErrorMsgContent;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.crmf.AttributeTypeAndValue;
import org.bouncycastle.asn1.crmf.CRMFObjectIdentifiers;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.crmf.OptionalValidity;
import org.bouncycastle.asn1.crmf.POPOSigningKey;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;
import org.ejbca.ui.cmpclient.CmpClientMessageHelper;

public class CrmfRequestCommand extends CmpCommandBase {

    private static final Logger log = Logger.getLogger(CrmfRequestCommand.class);
    
    private static final String COMMAND = "crmf";
    
    private static final String CMP_ALIAS_KEY = "--alias";
    private static final String SUBJECTDN_KEY = "--dn";
    private static final String ISSUERDN_KEY = "--issuer";
    private static final String DESTINATION_KEY = "--dest";
    private static final String AUTHENTICATION_MODULE_KEY = "--authmodule";
    private static final String AUTHENTICATION_PARAM_KEY = "--authparam";
    private static final String KEYSTORE_KEY = "--keystore";
    private static final String KEYSTOREPWD_KEY = "--keystorepwd";
    private static final String ALTNAME_KEY = "--altname";
    private static final String SERNO_KEY = "--serno";
    private static final String INCLUDE_POPO_KEY = "--includepopo";
    private static final String HOST_KEY = "--host";
    private static final String VERBOSE_KEY = "--v";
    
    //Register all parameters
    {
        registerParameter(new Parameter(CMP_ALIAS_KEY, "CMP Configuration Alias", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The CMP configuration alias"));
        registerParameter(new Parameter(SUBJECTDN_KEY, "SubjectDN", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The certificate's SubjectDN."));
        registerParameter(new Parameter(ISSUERDN_KEY, "IssuerDN", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The certificate's issuerDN"));
        registerParameter(new Parameter(DESTINATION_KEY, "Destination Directory", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The path to the directory where the newly issued certificate is stored. Default is './dest/'."));
        registerParameter(new Parameter(AUTHENTICATION_MODULE_KEY, "Authentication Module", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The authentication module used when creating the request. Default value: " + CmpConfiguration.AUTHMODULE_HMAC + ". " +
                "Possible values: " + CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD + ", " + CmpConfiguration.AUTHMODULE_HMAC + " or " + CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE + ".\n" +
                "\nWhen using " + CmpConfiguration.AUTHMODULE_HMAC + " authentication module: In RA mode, the value of the authentication parameter " +
                "should be the HMAC shared secret. In Client mode, it should be the end entity password (stored in clear text in EJBCA database)\n" +        
                "\nWhen using " + CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE + " authentication module, the value of the authentication " +
                "parameter should be the friendlyname in the keystore for the certificate that will be attached in the extraCerts field\n" +
                "\nIf you are using " +  CmpConfiguration.AUTHMODULE_DN_PART_PWD + ", set the SubjectDN part and the password in '" + SUBJECTDN_KEY + "' directly. " +
                "For example, if you want the subjectDN to be 'CN=foo,C=SE' and you want the password 'foo123' to be specified in the DN part 'OU', set the SubjectDN " +
                "as follows: '" + SUBJECTDN_KEY + " CN=foo,C=SE,OU=foo123'"));
        registerParameter(new Parameter(AUTHENTICATION_PARAM_KEY, "Authentication Parameter", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The authentication parameter is the parameter for the authentication module. Default value: foo123\n" +
                "\nWhen using " + CmpConfiguration.AUTHMODULE_HMAC + " authentication module: In RA mode, this value should be the HMAC shared secret. " +
                "In Client mode, it should be the end entity password (stored in clear text in EJBCA database)\n" +
                "\nWhen using " + CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE + " authentication module, this value should be the friendlyname in the keystore for " +
                "the certificate that will be attached in the extraCerts field\n" +       
                "\nIf you are using " +  CmpConfiguration.AUTHMODULE_DN_PART_PWD + ", set the SubjectDN part and the password in '" + SUBJECTDN_KEY + "' directly. " +
                "For example, if you want the subjectDN to be 'CN=foo,C=SE' and you want the password 'foo123' to be specified in the DN part 'OU', set the SubjectDN " +
                "as follows: '" + SUBJECTDN_KEY + " CN=foo,C=SE,OU=foo123'"));
        registerParameter(new Parameter(KEYSTORE_KEY, "Path to the keystore", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The path to the keystore containing the certificate and private key used to sign the request. Mandatory when " + CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE + 
                " authentication Module is used"));
        registerParameter(new Parameter(KEYSTOREPWD_KEY, "Keystore password", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The password to the keystore containing the private key used to sign the request. Mandatory when " + CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE + 
                " authentication Module is used"));
        registerParameter(new Parameter(ALTNAME_KEY, "SubjectAlternativeName", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The certificate's SubjectAlternativeName."));
        registerParameter(new Parameter(SERNO_KEY, "Certificate Serialnumber", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The custom certificate serialnumber in Hexadecimal format."));
        registerParameter(new Parameter(INCLUDE_POPO_KEY, "Include Proof-of-Possession", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.FLAG,
                "If present, a Proof-of-Possession is included in the CMP request"));
        registerParameter(new Parameter(HOST_KEY, "Host", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The name or IP adress to the CMP server. Default value is 'localhost'"));
        registerParameter(new Parameter(VERBOSE_KEY, "Verbose", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.FLAG,
                "Prints out extra messages while executing"));
    }
    
    @Override
    public String getMainCommand() {
        return COMMAND;
    }

    @Override
    public String getCommandDescription() {
        return "Sends a CRMF request and stores the returned certificate in a local directory. " +
        	   "The certificate file name will have the format <CN>.pem";
    }

    @Override
    protected CommandResult execute(ParameterContainer parameters) {
        try {
            final PKIMessage pkimessage = generatePKIMessage(parameters);
        
            String authmodule = parameters.get(AUTHENTICATION_MODULE_KEY);
            String authparam = parameters.get(AUTHENTICATION_PARAM_KEY);
            if(authmodule==null) {
                authmodule = CmpConfiguration.AUTHMODULE_HMAC;
                log.info("Using default authentication module: " + CmpConfiguration.AUTHMODULE_HMAC);
            }
            if(authparam==null) {
                authparam = "foo123";
                log.info("Using default value for authentication parameter: " + authparam);
            }
            final PKIMessage protectedPKIMessage = CmpClientMessageHelper.getInstance().createProtectedMessage(pkimessage, authmodule, authparam, 
                    parameters.get(KEYSTORE_KEY), parameters.get(KEYSTOREPWD_KEY), parameters.containsKey(VERBOSE_KEY)); 
        
            byte[] requestBytes = CmpClientMessageHelper.getInstance().getRequestBytes(protectedPKIMessage);
        
            String host =  parameters.get(HOST_KEY);
            if(host == null) {
                host = "127.0.0.1";
                log.info("Using default CMP Server IP address 'localhost'");
            }
            byte[] responseBytes = CmpClientMessageHelper.getInstance().sendCmpHttp(requestBytes, 200, parameters.get(CMP_ALIAS_KEY), host);
        
            return handleCMPResponse(responseBytes, parameters);
        } catch(Exception e) {
            e.printStackTrace();
        }
        return CommandResult.CLI_FAILURE;
    }

    @Override
    public PKIMessage generatePKIMessage(final ParameterContainer parameters) throws Exception {

        final boolean verbose = parameters.containsKey(VERBOSE_KEY);
        
        final X500Name userDN = new X500Name(parameters.get(SUBJECTDN_KEY));
        final X500Name issuerDN = new X500Name(parameters.get(ISSUERDN_KEY));
        
        String authmodule = parameters.get(AUTHENTICATION_MODULE_KEY);
        String endentityPassword = ""; 
        if(authmodule!=null && StringUtils.equals(authmodule , CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD)) { 
            endentityPassword = parameters.containsKey(AUTHENTICATION_PARAM_KEY) ? parameters.get(AUTHENTICATION_PARAM_KEY) : "foo123";
        }
        
        
        String altNames = parameters.get(ALTNAME_KEY);
        String serno = parameters.get(SERNO_KEY);
        BigInteger customCertSerno = null;
        if(serno!=null) {
            customCertSerno = new BigInteger(serno, 16);
        }
        boolean includePopo =  parameters.containsKey(INCLUDE_POPO_KEY);     
        
        if(verbose) {
            log.info("Creating CRMF request with: SubjectDN=" + userDN.toString());
            log.info("Creating CRMF request with: IssuerDN=" + issuerDN.toString());
            log.info("Creating CRMF request with: AuthenticationModule=" + authmodule);
            log.info("Creating CRMF request with: EndEntityPassword=" + endentityPassword);
            log.info("Creating CRMF request with: SubjectAltName=" + altNames);
            log.info("Creating CRMF request with: CustomCertSerno=" + (customCertSerno==null?"":customCertSerno.toString(16)));
            log.info("Creating CRMF request with: IncludePopo=" + includePopo);
        }
        
        
        final KeyPair keys = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        final byte[] nonce = CmpClientMessageHelper.getInstance().createSenderNonce();
        final byte[] transid = CmpClientMessageHelper.getInstance().createSenderNonce();
        

        
        
        // We should be able to back date the start time when allow validity
        // override is enabled in the certificate profile
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.DAY_OF_WEEK, -1);
        cal.set(Calendar.MILLISECOND, 0); // Certificates don't use milliseconds
        // in validity
        Date notBefore = cal.getTime();
        cal.add(Calendar.DAY_OF_WEEK, 3);
        cal.set(Calendar.MILLISECOND, 0); // Certificates don't use milliseconds
        org.bouncycastle.asn1.x509.Time nb = new org.bouncycastle.asn1.x509.Time(notBefore);
        // in validity
        Date notAfter = cal.getTime();
        org.bouncycastle.asn1.x509.Time na = new org.bouncycastle.asn1.x509.Time(notAfter);
        
        ASN1EncodableVector optionalValidityV = new ASN1EncodableVector();
        optionalValidityV.add(new DERTaggedObject(true, 0, nb));
        optionalValidityV.add(new DERTaggedObject(true, 1, na));
        OptionalValidity myOptionalValidity = OptionalValidity.getInstance(new DERSequence(optionalValidityV));
        
        
        
        
        CertTemplateBuilder myCertTemplate = new CertTemplateBuilder();
        myCertTemplate.setValidity(myOptionalValidity);
        if(issuerDN != null) {
            myCertTemplate.setIssuer(issuerDN);
        }
        myCertTemplate.setSubject(userDN);
        byte[] bytes = keys.getPublic().getEncoded();
        ByteArrayInputStream bIn = new ByteArrayInputStream(bytes);
        ASN1InputStream dIn = new ASN1InputStream(bIn);
        SubjectPublicKeyInfo keyInfo = new SubjectPublicKeyInfo((ASN1Sequence) dIn.readObject());
        dIn.close();
        myCertTemplate.setPublicKey(keyInfo);

        // Create standard extensions
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ASN1OutputStream dOut = new ASN1OutputStream(bOut);
        ExtensionsGenerator extgen = new ExtensionsGenerator();
        if (altNames != null) {
            GeneralNames san = CertTools.getGeneralNamesFromAltName(altNames);
            dOut.writeObject(san);
            byte[] value = bOut.toByteArray();
            extgen.addExtension(Extension.subjectAlternativeName, false, value);
        }
        
        // KeyUsage
        int bcku = 0;
        bcku = KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.nonRepudiation;
        KeyUsage ku = new KeyUsage(bcku);
        extgen.addExtension(Extension.keyUsage, false, new DERBitString(ku));
        
        // Make the complete extension package
        Extensions exts = extgen.generate();

        myCertTemplate.setExtensions(exts);
        if (customCertSerno != null) {
            // Add serialNumber to the certTemplate, it is defined as a MUST NOT be used in RFC4211, but we will use it anyway in order
            // to request a custom certificate serial number (something not standard anyway)
            myCertTemplate.setSerialNumber(new ASN1Integer(customCertSerno));
        }
        
        CertRequest myCertRequest = new CertRequest(4, myCertTemplate.build(), null);
        
        // POPO
        /*
         * PKMACValue myPKMACValue = new PKMACValue( new AlgorithmIdentifier(new
         * ASN1ObjectIdentifier("8.2.1.2.3.4"), new DERBitString(new byte[] { 8,
         * 1, 1, 2 })), new DERBitString(new byte[] { 12, 29, 37, 43 }));
         * 
         * POPOPrivKey myPOPOPrivKey = new POPOPrivKey(new DERBitString(new
         * byte[] { 44 }), 2); //take choice pos tag 2
         * 
         * POPOSigningKeyInput myPOPOSigningKeyInput = new POPOSigningKeyInput(
         * myPKMACValue, new SubjectPublicKeyInfo( new AlgorithmIdentifier(new
         * ASN1ObjectIdentifier("9.3.3.9.2.2"), new DERBitString(new byte[] { 2,
         * 9, 7, 3 })), new byte[] { 7, 7, 7, 4, 5, 6, 7, 7, 7 }));
         */
        ProofOfPossession myProofOfPossession = null;
        if(includePopo) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DEROutputStream mout = new DEROutputStream(baos);
            mout.writeObject(myCertRequest);
            mout.close();
            byte[] popoProtectionBytes = baos.toByteArray();            
            String    sigalg = AlgorithmTools.getSignAlgOidFromDigestAndKey(null, keys.getPrivate().getAlgorithm()).getId();
            Signature sig = Signature.getInstance(sigalg, "BC");
            sig.initSign(keys.getPrivate());
            sig.update(popoProtectionBytes);
            DERBitString bs = new DERBitString(sig.sign());
            POPOSigningKey myPOPOSigningKey = new POPOSigningKey(null, new AlgorithmIdentifier(new ASN1ObjectIdentifier(sigalg)), bs);
            myProofOfPossession = new ProofOfPossession(myPOPOSigningKey);
        } else {
            // raVerified POPO (meaning there is no POPO)
            myProofOfPossession = new ProofOfPossession();
        }
        
        AttributeTypeAndValue av = new AttributeTypeAndValue(CRMFObjectIdentifiers.id_regCtrl_regToken, new DERUTF8String(endentityPassword));
        AttributeTypeAndValue[] avs = {av};
        
        CertReqMsg myCertReqMsg = new CertReqMsg(myCertRequest, myProofOfPossession, avs);
        
        CertReqMessages myCertReqMessages = new CertReqMessages(myCertReqMsg);
        
        PKIHeaderBuilder myPKIHeader = new PKIHeaderBuilder(2, new GeneralName(userDN), new GeneralName(issuerDN));
                
        myPKIHeader.setMessageTime(new ASN1GeneralizedTime(new Date()));
        // senderNonce
        myPKIHeader.setSenderNonce(new DEROctetString(nonce));
        // TransactionId
        myPKIHeader.setTransactionID(new DEROctetString(transid));
        myPKIHeader.setProtectionAlg(null);
        myPKIHeader.setSenderKID(new byte[0]);
        
        PKIBody myPKIBody = new PKIBody(0, myCertReqMessages); // initialization
        // request
        PKIMessage myPKIMessage = new PKIMessage(myPKIHeader.build(), myPKIBody);
        
        return myPKIMessage;
    }

    @Override
    public CommandResult handleCMPResponse(byte[] response, final ParameterContainer parameters) throws Exception {
        String dest = parameters.get(DESTINATION_KEY);
        if(dest==null) {
            dest = "dest";
            new File("./" + dest).mkdirs();
            log.info("Using default destination directory: ./dest/");
        }
        
        PKIMessage respObject = null;
        ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(response));
        try {
            respObject = PKIMessage.getInstance(asn1InputStream.readObject());
        } finally {
            asn1InputStream.close();
        }
        if(respObject == null) {
            log.error("ERROR. Cannot construct the response object");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        
        PKIBody body = respObject.getBody();        
        int tag = body.getType();
        
        if(tag == PKIBody.TYPE_INIT_REP) {
            CertRepMessage c = (CertRepMessage) body.getContent();
            CertResponse resp = c.getResponse()[0];
            PKIStatusInfo status = resp.getStatus();
            if(status.getStatus().intValue() == PKIStatus.GRANTED) {
                final X509Certificate cert = getCertFromResponse(resp);
                final ArrayList<Certificate> certs = new ArrayList<>();
                certs.add(cert);
                final byte[] certBytes = CertTools.getPemFromCertificateChain(certs);
                
                String certFileName = getDestinationCertFile(dest, parameters.get(SUBJECTDN_KEY));
                final FileOutputStream fos = new FileOutputStream(new File(certFileName));
                fos.write(certBytes);
                fos.close();
                log.info("CRMF request successful. Received certificate stored in " + certFileName);
                return CommandResult.SUCCESS;
            } else {
                final String errMsg = status.getStatusString().getStringAt(0).getString();
                log.error("Recieved CRMF response with status '" + status.getStatus().intValue() + "' and error message: " + errMsg);
            }
        } else if(tag==PKIBody.TYPE_ERROR){
            ErrorMsgContent err = (ErrorMsgContent) body.getContent();
            final String errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
            log.error("Revceived CMP Error Message: " +  errMsg);
        } else {
            log.error("Received PKIMessage with body tag " + tag);
        }
        return CommandResult.FUNCTIONAL_FAILURE;
    }

    private X509Certificate getCertFromResponse(final CertResponse resp) throws Exception {
        final CertifiedKeyPair kp = resp.getCertifiedKeyPair();
        final CertOrEncCert cc = kp.getCertOrEncCert();
        final CMPCertificate cmpcert = cc.getCertificate();
        return (X509Certificate) CertTools.getCertfromByteArray(cmpcert.getEncoded());
    }
    
    private String getDestinationCertFile(final String destDirectory, final String subjectDN) {
        return destDirectory + (StringUtils.endsWith(destDirectory, "/")?"":"/") + CertTools.getPartFromDN(subjectDN, "CN") + ".pem";
    }
    
    @Override
    public String getFullHelpText() {
        return "";
    }

    @Override
    protected Logger getLogger() {
        return log;
    }


}
