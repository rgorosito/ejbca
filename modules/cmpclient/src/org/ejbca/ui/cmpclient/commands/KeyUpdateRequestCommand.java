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
import java.security.KeyPair;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERGeneralizedTime;
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
import org.bouncycastle.asn1.x509.GeneralName;
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


public class KeyUpdateRequestCommand extends CmpCommandBase {
    
    private static final Logger log = Logger.getLogger(KeyUpdateRequestCommand.class);

    private static final String COMMAND = "update";
    
    private static final String CMP_ALIAS_KEY = "--alias";
    private static final String SUBJECTDN_KEY = "--dn";
    private static final String ISSUERDN_KEY = "--issuer";
    private static final String DESTINATION_KEY = "--dest";
    private static final String EXTRACERT_FRIENDLYNAME_KEY = "--extraCertsFriendlyName";
    private static final String KEYSTORE_KEY = "--keystore";
    private static final String KEYSTOREPWD_KEY = "--keystorepwd";
    private static final String INCLUDE_POPO_KEY = "--includepopo";
    private static final String HOST_KEY = "--host";
    private static final String URL_KEY = "--url";
    private static final String VERBOSE_KEY = "--v";
    
    //Register all parameters
    {
        registerParameter(new Parameter(CMP_ALIAS_KEY, "CMP Configuration Alias", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The CMP configuration alias. Default value: cmp"));
        registerParameter(new Parameter(SUBJECTDN_KEY, "SubjectDN", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The certificate's SubjectDN."));
        registerParameter(new Parameter(ISSUERDN_KEY, "IssuerDN", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The certificate's issuerDN"));
        registerParameter(new Parameter(KEYSTORE_KEY, "Path to the keystore", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The path to the keystore containing the private key used to sign the request"));
        registerParameter(new Parameter(KEYSTOREPWD_KEY, "Keystore password", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The password to the keystore containing the certificate and private key used to sign the request"));
        registerParameter(new Parameter(EXTRACERT_FRIENDLYNAME_KEY, "ExtraCert Friendly Name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The friendlyname in the keystore for the certificate that will be attachded in the extraCerts field"));
        registerParameter(new Parameter(DESTINATION_KEY, "Destination Directory", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The path to the directory where the newly issued certificate is stored. Default is './dest/'."));
        registerParameter(new Parameter(INCLUDE_POPO_KEY, "Include Proof-of-Possession", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.FLAG,
                "If present, a Proof-of-Possession is included in the CMP request"));
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
        return "Sends a KeyUpdate request and stores the returned certificate in a local directory. " +
        	   "The certificate file name will have the format <CN>.pem";
    }

    @Override
    protected CommandResult execute(ParameterContainer parameters) {
        try {
            final PKIMessage pkimessage = generatePKIMessage(parameters);
        
            final PKIMessage protectedPKIMessage = CmpClientMessageHelper.getInstance().createProtectedMessage(pkimessage, 
                    CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE, parameters.get(EXTRACERT_FRIENDLYNAME_KEY), 
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
        
        final X500Name userDN = new X500Name(parameters.get(SUBJECTDN_KEY));
        final X500Name issuerDN = new X500Name(parameters.get(ISSUERDN_KEY));
        boolean includePopo =  parameters.containsKey(INCLUDE_POPO_KEY);
        
        if(verbose) {
            log.info("Creating KeyUpdate request with: SubjectDN=" + userDN.toString());
            log.info("Creating KeyUpdate request with: IssuerDN=" + issuerDN.toString());
            log.info("Creating KeyUpdate request with: IncludePopo=" + includePopo);
        }
        
        byte[] nonce = CmpClientMessageHelper.getInstance().createSenderNonce();
        byte[] transid = CmpClientMessageHelper.getInstance().createSenderNonce();
        KeyPair keys = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        
        CertTemplateBuilder myCertTemplate = new CertTemplateBuilder();

        ASN1EncodableVector optionalValidityV = new ASN1EncodableVector();
        org.bouncycastle.asn1.x509.Time nb = new org.bouncycastle.asn1.x509.Time(new DERGeneralizedTime("20030211002120Z"));
        org.bouncycastle.asn1.x509.Time na = new org.bouncycastle.asn1.x509.Time(new Date());
        optionalValidityV.add(new DERTaggedObject(true, 0, nb));
        optionalValidityV.add(new DERTaggedObject(true, 1, na));
        OptionalValidity myOptionalValidity = OptionalValidity.getInstance(new DERSequence(optionalValidityV));
        
        myCertTemplate.setValidity(myOptionalValidity);
        
        byte[] bytes = keys.getPublic().getEncoded();
        ByteArrayInputStream bIn = new ByteArrayInputStream(bytes);
        ASN1InputStream dIn = new ASN1InputStream(bIn);
        try {
            SubjectPublicKeyInfo keyInfo = new SubjectPublicKeyInfo((ASN1Sequence) dIn.readObject());
            myCertTemplate.setPublicKey(keyInfo);
        } finally {
            dIn.close();
        }
        
        myCertTemplate.setSubject(userDN);
        
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
            String sigalg = AlgorithmTools.getSignAlgOidFromDigestAndKey(null, keys.getPrivate().getAlgorithm()).getId();
            Signature sig = Signature.getInstance(sigalg);
            sig.initSign(keys.getPrivate());
            sig.update(popoProtectionBytes);
            
            DERBitString bs = new DERBitString(sig.sign());
            
            POPOSigningKey myPOPOSigningKey = new POPOSigningKey(null, new AlgorithmIdentifier(new ASN1ObjectIdentifier(sigalg)), bs);
            myProofOfPossession = new ProofOfPossession(myPOPOSigningKey);
        } else {
            // raVerified POPO (meaning there is no POPO)
            myProofOfPossession = new ProofOfPossession();
        }
         
        // myCertReqMsg.addRegInfo(new AttributeTypeAndValue(new
        // ASN1ObjectIdentifier("1.3.6.2.2.2.2.3.1"), new
        // DERInteger(1122334455)));
        AttributeTypeAndValue av = new AttributeTypeAndValue(CRMFObjectIdentifiers.id_regCtrl_regToken, new DERUTF8String(""));
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
        
        PKIBody myPKIBody = new PKIBody(PKIBody.TYPE_KEY_UPDATE_REQ, myCertReqMessages); // Key Update Request
        PKIMessage myPKIMessage = new PKIMessage(myPKIHeader.build(), myPKIBody);
        
        return myPKIMessage;
    }

    @Override
    public CommandResult handleCMPResponse(byte[] response, ParameterContainer parameters) throws Exception {
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
            log.error("Cannot construct response object");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        
        PKIBody body = respObject.getBody();
        int tag = body.getType();
        if(tag == PKIBody.TYPE_KEY_UPDATE_REP) {
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
            
        } else if(tag == PKIBody.TYPE_ERROR) {
            log.error("Error response was recieved");
            ErrorMsgContent c = (ErrorMsgContent) body.getContent();
            PKIStatusInfo info = c.getPKIStatusInfo();
            log.error("Error message: " + info.getStatusString().getStringAt(0));
        } else {
            log.error("Recieved response with body type(See PKIBody.java): " + tag);
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
        return "The KeyUpdate request always uses " + CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE + " authentication module";
    }
    
    protected Logger getLogger() {
        return log;
    }

}
