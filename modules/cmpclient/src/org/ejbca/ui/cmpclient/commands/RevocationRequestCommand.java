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
import java.math.BigInteger;
import java.util.Date;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmp.ErrorMsgContent;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.cmp.RevDetails;
import org.bouncycastle.asn1.cmp.RevRepContent;
import org.bouncycastle.asn1.cmp.RevReqContent;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;
import org.ejbca.ui.cmpclient.CmpClientMessageHelper;

public class RevocationRequestCommand extends CmpCommandBase {
    
    private static final Logger log = Logger.getLogger(RevocationRequestCommand.class);
    
    public static final String REVOCATION_REASON_UNSPECIFIED = "unspecified";
    public static final String REVOCATION_REASON_KEYCOMPROMISE = "keyCompromise";
    public static final String REVOCATION_REASON_CACOMPROMISE = "caCompromise";
    public static final String REVOCATION_REASON_AFFILIATIONCHANGED = "affiliationChanged";
    public static final String REVOCATION_REASON_SUPERSEDED = "superseded";
    public static final String REVOCATION_REASON_CESSATIONOFOPERATION = "cessationOfOperation";
    public static final String REVOCATION_REASON_CERTIFICATEHOLD = "certificateHold";
    
    
    private static final String COMMAND = "revoke";
    
    private static final String CMP_ALIAS_KEY = "--alias";
    private static final String ISSUERDN_KEY = "--issuer";
    private static final String SERNO_KEY = "--serno";
    private static final String REVOCATION_REASON_KEY = "--reason";
    private static final String AUTHENTICATION_MODULE_KEY = "--authmodule";
    private static final String AUTHENTICATION_PARAM_KEY = "--authparam";
    private static final String KEYSTORE_KEY = "--keystore";
    private static final String KEYSTOREPWD_KEY = "--keystorepwd";
    private static final String HOST_KEY = "--host";
    private static final String URL_KEY = "--url";
    private static final String VERBOSE_KEY = "--v";
    
    //Register all parameters
    {
        registerParameter(new Parameter(CMP_ALIAS_KEY, "CMP Configuration Alias", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The CMP configuration alias. Default value: cmp"));
        registerParameter(new Parameter(ISSUERDN_KEY, "IssuerDN", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The IssuerDN of the certificate to be removed"));
        registerParameter(new Parameter(SERNO_KEY, "Certificate Serialnumber", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The serialnumber of the certificate to be removed in Hexadecimal format."));
        registerParameter(new Parameter(REVOCATION_REASON_KEY, "Revocation Reason", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The revocation reason. Default value: " + REVOCATION_REASON_UNSPECIFIED + ". Possible values: " + getPossibleRevocationReasons()));
        registerParameter(new Parameter(AUTHENTICATION_MODULE_KEY, "Authentication Module", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The authentication module used when creating the request. Default value: " + CmpConfiguration.AUTHMODULE_HMAC + ". " +
                "Possible values: " + CmpConfiguration.AUTHMODULE_HMAC + " or " + CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE + "\n" +
                "\nWhen using " + CmpConfiguration.AUTHMODULE_HMAC + " authentication module: In RA mode, the value of the authentication parameter " +
                "should be the HMAC shared secret. In Client mode, it should be the end entity password (stored in clear text in EJBCA database)\n" +
                "\nWhen using " + CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE + " authentication module, the value of the authentication " +
                "parameter should be the friendlyname in the keystore for the certificate that will be attached in the extraCerts field"));
        registerParameter(new Parameter(AUTHENTICATION_PARAM_KEY, "Authentication Parameter", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The authentication parameter is the parameter for the authentication module. Default value: foo123\n" +
                "\nWhen using " + CmpConfiguration.AUTHMODULE_HMAC + " authentication module: In RA mode, this value should be the HMAC shared secret. " +
                "In Client mode, it should be the end entity password (stored in clear text in EJBCA database)\n" +
                "\nWhen using " + CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE + " authentication module, this value should be the friendlyname in the keystore for " +
                "the certificate that will be attached in the extraCerts field"));
        registerParameter(new Parameter(KEYSTORE_KEY, "Path to the keystore", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The path to the keystore containing the certificate and private key used to sign the request. Mandatory when " + CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE + 
                " authentication Module is used"));
        registerParameter(new Parameter(KEYSTOREPWD_KEY, "Keystore password", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The password to the keystore containing the private key used to sign the request. Mandatory when " + CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE + 
                " authentication Module is used"));
        registerParameter(new Parameter(HOST_KEY, "Host", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The name or IP adress to the CMP server. Default value is 'localhost'"));
        registerParameter(new Parameter(URL_KEY, "URL", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The whole URL to the CMP server. This URL must include the CMP configuration alias. Default: http://localhost:8080/ejbca/publicweb/cmp/<CmpConfigurationAlias>"));
        registerParameter(new Parameter(VERBOSE_KEY, "Verbose", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.FLAG,
                "Prints out extra messages while executing"));
    }

    @Override
    public String getMainCommand() {
        return COMMAND;
    }

    @Override
    public String getCommandDescription() {
        return "Sends a CMP revocation request and displays the result";
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
        
            byte[] responseBytes = CmpClientMessageHelper.getInstance().sendCmpHttp(requestBytes, 200, 
                    parameters.get(CMP_ALIAS_KEY), parameters.get(HOST_KEY), parameters.get(URL_KEY));
        
            return handleCMPResponse(responseBytes, parameters);
        } catch(Exception e) {
            e.printStackTrace();
        }
        return CommandResult.CLI_FAILURE;
    }
    
    @Override
    public PKIMessage generatePKIMessage(ParameterContainer parameters) throws Exception {
        boolean verbose = parameters.containsKey(VERBOSE_KEY);
        
        final X500Name userDN  = new X500Name("CN=foo");
        final X500Name issuerDN = new X500Name(parameters.get(ISSUERDN_KEY));
        BigInteger serno = new BigInteger(parameters.get(SERNO_KEY), 16);
        
        if(verbose) {
            log.info("Creating revocation request with: SubjectDN=" + userDN.toString());
            log.info("Creating revocation request with: IssuerDN=" + issuerDN.toString());
            log.info("Creating revocation request with: CertSerno=" + serno.toString(16));
        }
        
        byte[] nonce = CmpClientMessageHelper.getInstance().createSenderNonce();
        byte[] transid = CmpClientMessageHelper.getInstance().createSenderNonce();
        
        CertTemplateBuilder myCertTemplate = new CertTemplateBuilder();
        myCertTemplate.setIssuer(issuerDN);
        myCertTemplate.setSubject(userDN);
        myCertTemplate.setSerialNumber(new ASN1Integer(serno));

        ExtensionsGenerator extgen = new ExtensionsGenerator();
        extgen.addExtension(Extension.reasonCode, false, getCRLReason(parameters.get(REVOCATION_REASON_KEY)));
        
        Extensions exts = extgen.generate();
        
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(myCertTemplate.build());
        v.add(exts);
        ASN1Sequence seq = new DERSequence(v);
        
        RevDetails myRevDetails = RevDetails.getInstance(seq);
        
        RevReqContent myRevReqContent = new RevReqContent(myRevDetails);

        PKIHeaderBuilder myPKIHeader = new PKIHeaderBuilder(2, new GeneralName(userDN), new GeneralName(issuerDN));
        myPKIHeader.setMessageTime(new ASN1GeneralizedTime(new Date()));
        // senderNonce
        myPKIHeader.setSenderNonce(new DEROctetString(nonce));
        // TransactionId
        myPKIHeader.setTransactionID(new DEROctetString(transid));
        myPKIHeader.setProtectionAlg(null);
        myPKIHeader.setSenderKID(new byte[0]);

        PKIBody myPKIBody = new PKIBody(PKIBody.TYPE_REVOCATION_REQ, myRevReqContent); // revocation request
        PKIMessage myPKIMessage = new PKIMessage(myPKIHeader.build(), myPKIBody);
        return myPKIMessage;
    }
    
    private CRLReason getCRLReason(String revreason) {
        if(revreason == null) return CRLReason.lookup(CRLReason.unspecified);
        if(StringUtils.equalsIgnoreCase(revreason, REVOCATION_REASON_UNSPECIFIED)) return CRLReason.lookup(CRLReason.unspecified); 
        if(StringUtils.equalsIgnoreCase(revreason, REVOCATION_REASON_KEYCOMPROMISE)) return CRLReason.lookup(CRLReason.keyCompromise);
        if(StringUtils.equalsIgnoreCase(revreason, REVOCATION_REASON_CACOMPROMISE)) return CRLReason.lookup(CRLReason.cACompromise);
        if(StringUtils.equalsIgnoreCase(revreason, REVOCATION_REASON_AFFILIATIONCHANGED)) return CRLReason.lookup(CRLReason.affiliationChanged);
        if(StringUtils.equalsIgnoreCase(revreason, REVOCATION_REASON_SUPERSEDED)) return CRLReason.lookup(CRLReason.superseded);
        if(StringUtils.equalsIgnoreCase(revreason, REVOCATION_REASON_CESSATIONOFOPERATION)) return CRLReason.lookup(CRLReason.cessationOfOperation);
        if(StringUtils.equalsIgnoreCase(revreason, REVOCATION_REASON_CERTIFICATEHOLD)) return CRLReason.lookup(CRLReason.certificateHold);
        return CRLReason.lookup(CRLReason.unspecified);
    }

    @Override
    public CommandResult handleCMPResponse(byte[] response, ParameterContainer parameters) throws Exception {
        PKIMessage respObject = null;
        ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(response));
        try {
            respObject = PKIMessage.getInstance(asn1InputStream.readObject());
        } finally {
            asn1InputStream.close();
        }
        if(respObject == null) {
            log.error("Cannot construct response object");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        
        PKIBody body = respObject.getBody();
        int tag = body.getType();
        if(tag == PKIBody.TYPE_REVOCATION_REP) {
            log.info("Revocation response was recieved");
            RevRepContent n = (RevRepContent) body.getContent();
            PKIStatusInfo info = n.getStatus()[0];
            if(info.getStatus().intValue() == 0) {
                log.info("Revocation request have succeeded");
                return CommandResult.SUCCESS;
            } else {
                log.error("Revocation request failed with status (See PKIStatusInfo.java): " + info.getStatus().intValue());
            }
        } else if(tag == PKIBody.TYPE_ERROR) {
            log.error("Error response was recieved");
            ErrorMsgContent c = (ErrorMsgContent) body.getContent();
            PKIStatusInfo info = c.getPKIStatusInfo();
            log.error("Error message: " + info.getStatusString().getStringAt(0).getString());
        } else {
            log.error("Recieved response with body type(See PKIBody.java): " + tag);
        }
        return CommandResult.FUNCTIONAL_FAILURE;
    }

    @Override
    public String getFullHelpText() {
        return "'CN=foo' is used as SubjectDN in the revocation request because the SubjectDN is irrelevant on the server side";
    }
    
    public static String getPossibleRevocationReasons() {
        StringBuilder ret = new StringBuilder("");
        ret.append(REVOCATION_REASON_UNSPECIFIED).append(", ");
        ret.append(REVOCATION_REASON_KEYCOMPROMISE).append(", ");
        ret.append(REVOCATION_REASON_CACOMPROMISE).append(", ");
        ret.append(REVOCATION_REASON_AFFILIATIONCHANGED).append(", ");
        ret.append(REVOCATION_REASON_SUPERSEDED).append(", ");
        ret.append(REVOCATION_REASON_CESSATIONOFOPERATION).append(", ");
        ret.append(REVOCATION_REASON_CERTIFICATEHOLD);
        return ret.toString();
    }
    
    protected Logger getLogger() {
        return log;
    }

}
