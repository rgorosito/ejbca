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

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmp.CertConfirmContent;
import org.bouncycastle.asn1.cmp.CertStatus;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIConfirmContent;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;
import org.ejbca.ui.cmpclient.CmpClientMessageHelper;

public class ConfirmationRequestCommand extends CmpCommandBase {

    private static final Logger log = Logger.getLogger(ConfirmationRequestCommand.class);
    
    private static final String COMMAND = "confirm";
    
    private static final String CMP_ALIAS_KEY = "--alias";
    private static final String ISSUERDN_KEY = "--issuer";
    private static final String AUTHENTICATION_MODULE_KEY = "--authmodule";
    private static final String AUTHENTICATION_PARAM_KEY = "--authparam";
    private static final String KEYSTORE_KEY = "--keystore";
    private static final String KEYSTOREPWD_KEY = "--keystorepwd";
    private static final String HOST_KEY = "--host";
    private static final String VERBOSE_KEY = "--v";
    
    //Register all parameters
    {
        registerParameter(new Parameter(CMP_ALIAS_KEY, "CMP Configuration Alias", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The CMP configuration alias"));
        registerParameter(new Parameter(ISSUERDN_KEY, "IssuerDN", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The certificate's issuerDN"));
        registerParameter(new Parameter(AUTHENTICATION_MODULE_KEY, "Authentication Module", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The authentication module used when creating the request. Default value: " + CmpConfiguration.AUTHMODULE_HMAC + ". " +
                "Possible values: " + CmpConfiguration.AUTHMODULE_HMAC + " or " + CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE + ".\n" +
                "\nWhen using " + CmpConfiguration.AUTHMODULE_HMAC + " authentication module: In RA mode, the value of the authentication parameter " +
                "should be the HMAC shared secret. In Client mode, it should be the end entity password (stored in clear text in EJBCA database)\n" +        
                "\nWhen using " + CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE + " authentication module, the value of the authentication " +
                "parameter should be the friendlyname in the keystore for the certificate that will be attached in the extraCerts field"));
        registerParameter(new Parameter(AUTHENTICATION_PARAM_KEY, "Authentication Parameter", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The authentication parameter is the parameter for the authentication module. Default value: foo123\n" +
                "\nWhen using " + CmpConfiguration.AUTHMODULE_HMAC + " authentication module: In RA mode, this value should be the HMAC shared secret. " +
                "In Client mode, it should be the end entity password (stored in clear text in EJBCA database)" + 
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
        registerParameter(new Parameter(VERBOSE_KEY, "Verbose", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.FLAG,
                "Prints out extra info messages while executing"));
    
    }
    
    @Override
    public String getMainCommand() {
        return COMMAND;
    }

    @Override
    public String getCommandDescription() {
        return "Sends a CMP confirmation request and displays the result";
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
                log.info("Using default authentication parameter: " + authparam);
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
    public PKIMessage generatePKIMessage(ParameterContainer parameters) throws Exception {

        final boolean verbose = parameters.containsKey(VERBOSE_KEY);
        
        final X500Name userDN = new X500Name("CN=foo");
        String issuer = parameters.get(ISSUERDN_KEY);
        if(issuer==null) {
            issuer = "CN=foobar";
            log.info("Using default issuerDN: " + issuer);
        }
        final X500Name issuerDN = new X500Name(issuer);
        
        if(verbose) {
            log.info("Creating confirmation request with: SubjectDN=" + userDN.toString());
            log.info("Creating confirmation request with: IssuerDN=" + issuerDN.toString());
        }
        
        byte[] nonce = CmpClientMessageHelper.getInstance().createSenderNonce();
        byte[] transid = CmpClientMessageHelper.getInstance().createSenderNonce();
        byte[] hash = new byte[0];
        
        PKIHeaderBuilder myPKIHeader = new PKIHeaderBuilder(2, new GeneralName(userDN), 
                                                               new GeneralName(issuerDN));
        myPKIHeader.setMessageTime(new ASN1GeneralizedTime(new Date()));
        // senderNonce
        myPKIHeader.setSenderNonce(new DEROctetString(nonce));
        // TransactionId
        myPKIHeader.setTransactionID(new DEROctetString(transid));

        CertStatus cs = new CertStatus(hash, new BigInteger("0"));
        
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(cs);
        CertConfirmContent cc = CertConfirmContent.getInstance(new DERSequence(v));
        
        PKIBody myPKIBody = new PKIBody(PKIBody.TYPE_CERT_CONFIRM, cc); // Cert Confirm
        PKIMessage myPKIMessage = new PKIMessage(myPKIHeader.build(), myPKIBody);
        return myPKIMessage;
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
            log.error("ERROR. Cannot construct the response object");
            return CommandResult.FUNCTIONAL_FAILURE;
        }

        PKIBody body = respObject.getBody();
        int tag = body.getType();
        if(tag==19) {
            log.info("Recieved CmpConfirmResponse");
        } else {
            log.error("Error: CmpConfirmResponse should be recieved. Instead, received response with tag " + tag);
        }
        PKIConfirmContent n = (PKIConfirmContent) body.getContent();
        
        if(n.toASN1Primitive().equals(DERNull.INSTANCE)) {
            log.info("CmpConfirmResponse contains DERNull as expected.");
            return CommandResult.SUCCESS;
        } else {
            log.error("Error: CmpConfirmResponse should contain DERNull. It did not.");
        }
        return CommandResult.FUNCTIONAL_FAILURE;
    }



    @Override
    public String getFullHelpText() {
        StringBuilder text = new StringBuilder("");
        text.append("NOTE!! Using a CMP confirmation is not recommended and should be avoided\n");
        text.append("\n");
        text.append("The confirmation request is built with the following parameters:\n");
        text.append("   SubjectDN               : CN=foo\n");
        text.append("   Certificate hash        : empty byte array\n");
        text.append("   Certificate request ID  : 0\n");
        text.append("\n");
        text.append("Expected a Confirmation response containing DERNull\n");
        text.append("\n");
        text.append("Using an IssuerDN that does not exist in the server results in a failed request if 'Default CA' for Confirmation request is not set " +
                "for the used CMP configuration alias on the server\n");
        return text.toString();
    }
    
    protected Logger getLogger() {
        return log;
    }

}
