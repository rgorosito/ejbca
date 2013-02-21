/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.extra.ra;

import java.io.FileInputStream;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Vector;

import javax.persistence.EntityManagerFactory;
import javax.persistence.Persistence;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.extra.db.Message;
import org.ejbca.extra.db.MessageHome;
import org.ejbca.extra.db.PKCS10Request;
import org.ejbca.extra.db.PKCS10Response;
import org.ejbca.extra.db.PKCS12Request;
import org.ejbca.extra.db.PKCS12Response;
import org.ejbca.extra.db.SubMessages;
import org.ejbca.extra.util.RAKeyStore;

/**
 * A test client for the External RA API that can be used for simple load and performance test and
 * to figure out expected response times for different types of requests.
 * 
 * Important, if signing is used must the RA server key store be configured as an 'Super
 * Administrator' in EJBCA.
 * 
 * @version $Id$
 */
public class ExtRATestClient {
	
	private static final Log log = LogFactory.getLog(ExtRATestClient.class);
	
	//private static final String TYPE_CERT     = "CERT";
	private static final String TYPE_KEYSTORE = "KEYSTORE";
	
	private static final String SECURITY_UNSECURED       = "UNSECURED";
	private static final String SECURITY_SIGNED          = "SIGNED";
	private static final String SECURITY_ENCRYPTED       = "ENCRYPTED";
	private static final String SECURITY_SIGNEDENCRYPTED = "SIGNEDENCRYPTED";
	
	private static final int ARG_TYPE            = 0;
	private static final int ARG_KEYSTOREPATH    = 1;
	private static final int ARG_PASSWORD        = 2;
	private static final int ARG_ENCRYPTIONCERT  = 3;
	private static final int ARG_SECURITYLEVEL   = 4;
	private static final int ARG_REQUESTSPERMIN  = 5;
	private static final int ARG_CONCURRENTRAS   = 6;
	private static final int ARG_WAITTIME        = 7;

    protected PrivateKey raKey = null;
    protected X509Certificate raCert = null;
    protected Vector<Certificate> cAChain = null;
    protected X509Certificate encCert = null;
    protected String securitylevel = SECURITY_UNSECURED;
	
    protected boolean requestKeyStore = false;
	
	protected int reqPerMin = 10;
	private int concurrentRAs = 2;
    protected int waitTime = 30;
	
    protected int generateUserRequests = 0;
	
	protected SecureRandom random = new SecureRandom();		
	
    protected static final String pkcs10_1 = 
		 "MIIBkzCB/QIBADBUMQswCQYDVQQGEwJTRTETMBEGA1UECBMKU29tZS1TdGF0ZTEh"
		+"MB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMQ0wCwYDVQQDEwRUZXN0"
		+"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDczgi13kcTGTMmOdMU/QzvH6JV"
		+"QxL23dqdYpsV//XHO2bjKlgqqc3MpGH4QQkz/80rzFi4EwuqBpOnXo0P09I2jztk"
		+"IG4TSM+RwOfvaAMDJ1B6eeih6JX+v0A5PaWJlx1nshUuikcYJK3iNVepy39li0m3"
		+"OBwub9NnnVWXuClUGwIDAQABoAAwDQYJKoZIhvcNAQEEBQADgYEAz4NpjNraufWg"
		+"ZDv5J1muOHwZvOO9Is1L8WvMLG+jgH8Q2rPpDq8buIIWDy6VK8ghr7xhZzEZznTX"
		+"5HLSLB1a6KvktiVSKB0nmAmDU28xXLWWwkA7/68J6DvAipk00bHdxuEJ4+Mg8UJ0"
		+"Mr+aXDlmZUfghzlB70dDUy/Np/YJVb8=";
	
	private MessageHome msghome = null; 

	ExtRATestClient(String[] args) throws Exception {
    	CryptoProviderTools.installBCProvider();
		if(args.length != 8){
			log.debug("Number of arguments: " + args.length);
			help();
			System.exit(-1); // NOPMD, it's not a JEE app
		}else{
			requestKeyStore = args[ARG_TYPE].equalsIgnoreCase(TYPE_KEYSTORE);
			EntityManagerFactory entityManagerFactory = Persistence.createEntityManagerFactory("external-ra-cli");
            msghome = new MessageHome(entityManagerFactory, MessageHome.MESSAGETYPE_EXTRA, true);
			securitylevel = args[ARG_SECURITYLEVEL];
			if(!securitylevel.equalsIgnoreCase(SECURITY_UNSECURED) &&
			   !securitylevel.equalsIgnoreCase(SECURITY_SIGNED) &&
			   !securitylevel.equalsIgnoreCase(SECURITY_ENCRYPTED) &&
			   !securitylevel.equalsIgnoreCase(SECURITY_SIGNEDENCRYPTED)){
				throw new Exception("Invalid SecurityLevel: "+securitylevel);
			}
			if(securitylevel.equalsIgnoreCase(SECURITY_SIGNED) || securitylevel.equalsIgnoreCase(SECURITY_SIGNEDENCRYPTED)){
			  RAKeyStore rakeystore = new RAKeyStore(args[ARG_KEYSTOREPATH], args[ARG_PASSWORD]);			 
			  Certificate[] chain = rakeystore.getKeyStore().getCertificateChain(rakeystore.getAlias());
			  cAChain = new Vector<Certificate>();
			  for(int i=0; i< chain.length ; i++){
				  if(((X509Certificate) chain[i]).getBasicConstraints() != -1){
				    cAChain.add(chain[i]);
				  }
			  }
			  raKey = (PrivateKey) rakeystore.getKeyStore().getKey(rakeystore.getAlias(), args[ARG_PASSWORD].toCharArray());
			  raCert = (X509Certificate) rakeystore.getKeyStore().getCertificate(rakeystore.getAlias());
			}
			if(securitylevel.equalsIgnoreCase(SECURITY_ENCRYPTED) || securitylevel.equalsIgnoreCase(SECURITY_SIGNEDENCRYPTED)){
		        CertificateFactory cf = CertTools.getCertificateFactory();
		        encCert = (X509Certificate) cf.generateCertificate(new FileInputStream(args[ARG_ENCRYPTIONCERT]));
			}
			reqPerMin = Integer.parseInt(args[ARG_REQUESTSPERMIN]);
			concurrentRAs = Integer.parseInt(args[ARG_CONCURRENTRAS]);
			waitTime = Integer.parseInt(args[ARG_WAITTIME]);			
		}
	}


	public static void main(String[] args) throws Exception {
      ExtRATestClient testclient = new ExtRATestClient(args);
      testclient.run();
	}
	
	
	public void help(){
		System.out.println("External RA API Test Client");
		System.out.println("Usage :  <CERT | KEYSTORE> <KeyStorePath> <KeyStorePwd> <EncCert> <SecurityLevel> <RequestsPerMin> <ConcurrentRAs> <WaitTime>");
		System.out.println("Where :");
		System.out.println(" <CERT | KEYSTORE> : Type of test, CERT creates single PKCS10 requests, KEYSTORE creates one PKCS10 and one PKCS12 request for each message" );
		System.out.println(" <KeyStorePath>    : The path to the keystore used to sign/encrypt messages. Use NOKEYSTORE for unencrypted security level.");
		System.out.println(" <KeyStorePwd>     : Password to unlock the keystore,. Use NOPWD for unencrypted security level.");
		System.out.println(" <EncCert>         : Path to certificate (DER) used to encrypt messages,. Use NOCERT for unencrypted security level.");
		System.out.println(" <SecurityLevel>   : Security Level, Valid values are " + SECURITY_UNSECURED + ", " + SECURITY_SIGNED + ", " + SECURITY_ENCRYPTED + ", " + SECURITY_SIGNEDENCRYPTED +"");
		System.out.println(" <RequestsPerMin>  : Requests to generate every minute per concurrent RA.");
		System.out.println(" <ConcurrentRAs>   : Number of concurrent RAs that will create requests.");
		System.out.println(" <WaitTime>        : Number of seconds to wait for answer before exception is thrown.\n\n");
		System.out.println("The database connection is configured in META-INF/persistence.xml. The JDBC driver JAR should be copied to the endorsed directory.\n");
		System.out.println("Examples : ");
		System.out.println("  Simple test sending unsecured requests every 5 s in one thread ");
		System.out.println("  expecting an answer within 60 s :");
		System.out.println("    java -jar externalra-cli.jar CERT NOKEYSTORE NOPWD NOCERT " + SECURITY_UNSECURED + " 12 1 60 \n");
		System.out.println("  Advanced test using encrypted and signed requests for pkcs10 cert and a pkcs12 keystore ");
		System.out.println("  every 1 min in two threads, expecting an answer within 60 s :");
		System.out.println("    java -jar externalra-cli.jar KEYSTORE rakeystore.p12 foo123 enccert.cer SIGNEDENCRYPTED 1 2 60 \n");
	}
	
	/**
	 * Starts the test application
	 */
	public void run(){
		for(int i=1; i <= concurrentRAs; i++){
			ConcurrentRAThread rAThread = new ConcurrentRAThread("Thread-"+i);
			println("Starting new Thread : " + "Thread-"+i);
			rAThread.start();					
		}
	}
	
	public synchronized void createUser(String username, SubMessages submessages){
	   msghome.create(username, submessages);
    }
	
	public synchronized Message findByUser(String username){
	  return msghome.findByMessageId(username);
	}
	
	public synchronized void println(String message){
		  System.out.println(message);
		  System.out.flush();
	}
	  
	private class ConcurrentRAThread extends Thread { // NOPMD, it's not a JEE app
		private boolean run = false;
		private String threadName = "";		
		private long serialNumber = 0;
		
		public ConcurrentRAThread(String threadName) {
		   	this.threadName = threadName;
		}

		public void run() {	   
			run=true;
			while(run) {
				try {
					// Start Request Thread
					RequestThread reqThread = new RequestThread(threadName, serialNumber++);
					reqThread.start();		                	  

				} catch(Exception e) {
					e.printStackTrace();
				}
				try {
					sleep(getTimeToNextRequests());  
				} catch( InterruptedException e) {}
			}
		}

		private long getTimeToNextRequests() {			
			return (60000 / reqPerMin) + (random.nextLong() % 1000);
		}

		public void stopThread() {
			this.run = false;
		}
	}
	
	private class RequestThread extends Thread { // NOPMD, it's not a JEE app
		private boolean run = false;
		private String threadName = "";
		private long serialNumber = 0;
		
		public RequestThread(String threadName, long serialNumber) {
		   	this.threadName = threadName;
		   	this.serialNumber = serialNumber;
		}

		public void run() {
			// Generate request
			String username = "TEST_" + threadName + "_REQ-" + serialNumber;
			long pkcs10RequestId = 0;
			long pkcs12RequestId = 0;
			long starttime = new Date().getTime();
			SubMessages submgs = generateSubMessage();
			pkcs10RequestId = createPKCS10Request(username,submgs);
			if (requestKeyStore) {
				pkcs12RequestId = createPKCS12Request(username,submgs);
			}
			createUser(username, submgs);			

			run=true;
			// Wait for response
			boolean processed = false;
			Message msg = null;
			int wait = waitTime;
			while (wait >= 0 && run) {
				msg = findByUser(username);
				if (msg != null && msg.getStatus().equals(Message.STATUS_PROCESSED)) {
					processed = true;
					break;
				}
				try {
					sleep(1000);
				} catch (InterruptedException e) {
				}
				wait--;
			}
			if (!processed) {
				println("Error : Couldn't get processed response within the specified waitTime : Username :" + username + ", WaitTime : " + waitTime);

			} else {
				SubMessages respmsgs = null;
				if (raKey != null) {					
					respmsgs = msg.getSubMessages(raKey,cAChain);
				} else {
					respmsgs = msg.getSubMessages(null,null);
				}
				PKCS10Response pkcs10resp = (PKCS10Response) respmsgs.getSubMessages().get(0);
				PKCS12Response pkcs12resp = null;
				if (requestKeyStore) {
					pkcs12resp = (PKCS12Response) respmsgs.getSubMessages().get(1);
				}
				if (pkcs10resp.getRequestId() !=  pkcs10RequestId) {
					println("Error in PKCS10 Request requestId doesn't match responseId for user : " + username + ", request Id : " + pkcs10RequestId + " = " +  pkcs10resp.getRequestId());
				}
				if (requestKeyStore && pkcs12resp.getRequestId() !=  pkcs12RequestId) {
					println("Error in PKCS12 Request requestId doesn't match responseId for user : " + username + ", request Id : " + pkcs12RequestId + " = " +  pkcs12resp.getRequestId());
				}
				if (!pkcs10resp.isSuccessful()) {
					println("Error in PKCS10 Request for user : " + username + ", message : " + pkcs10resp.getFailInfo());
				}
				if (requestKeyStore && !pkcs12resp.isSuccessful()) {
					println("Error in PKCS12 Request for user : " + username + ", message : " + pkcs12resp.getFailInfo());										
				}
				long endtime = new Date().getTime();
				float processtime = ((float) (endtime - starttime)) / 1000;
				if (pkcs10resp.isSuccessful() && !requestKeyStore) {					 
					println("  " + username + " Generated Sucessfully in " + processtime + " seconds, Total Requests " + ++generateUserRequests);
				}
				if (requestKeyStore && pkcs10resp.isSuccessful() && pkcs12resp.isSuccessful()) {
					println("  " + username + " Generated Sucessfully in " + processtime + " seconds, Total Requests " + ++generateUserRequests);
				}
			}

		}

		private long createPKCS10Request(String username, SubMessages submessages) {
			long requestId = random.nextLong();			
			submessages.addSubMessage(new PKCS10Request(requestId,username, "CN=PKCS10REQ", "RFC822NAME=PKCS10Request@test.com",
                    "PKCS10Request@test.com", null, "EMPTY", "ENDUSER", "ManagementCA",pkcs10_1));					
			return requestId;
		}
		
		private long createPKCS12Request(String username, SubMessages submessages) {
			long requestId = random.nextLong();			
			submessages.addSubMessage(new PKCS12Request(requestId,username, "CN=PKCS12REQ", "RFC822NAME=PKCS12Request@test.com",
                    "PKCS12Request@test.com", null, "EMPTY", "ENDUSER", 
                    "ManagementCA","foo123",PKCS12Request.KEYALG_RSA, "1024", true)); 
			return requestId;
		}
		
		private SubMessages generateSubMessage() {
			if(securitylevel.equalsIgnoreCase(SECURITY_SIGNEDENCRYPTED)){
				return new SubMessages(raCert,raKey, encCert);					                
			}
			if(securitylevel.equalsIgnoreCase(SECURITY_SIGNED)){
				return new SubMessages(raCert,raKey,null);	                
			}
			if(securitylevel.equalsIgnoreCase(SECURITY_ENCRYPTED)){
				return new SubMessages(null,null,encCert);					                
			}
			return new SubMessages(null,null,null);
		}

		public void stopThread() {
		  	this.run = false;
		}
	}
}
