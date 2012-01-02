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
package org.ejbca.extra.db;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.util.encoders.Base64;

/**
 * Class used 
 * 
 * @author Philip Vendil
 * @version $Id$
 */
public class SubMessages {
	
	private static final Log log = LogFactory.getLog(SubMessages.class);
	
	private ArrayList<ISubMessage> submessages = new ArrayList<ISubMessage>();
	
	private boolean isSigned = false;
	
	private boolean isEncrypted = false;
	
	private transient X509Certificate userCert = null;
	private transient PrivateKey userKey = null;
	private transient X509Certificate encCert = null;

	private X509Certificate signerCert;
	
	/**
	 * Constructor to use when creating a SubMessages.
	 * 
	 * @param userCert certificate used for signing the request and used for encryption by 
	 * the responding service. Set this to null if no request signing should be performed.
	 * @param userKey Key to use as signing, set to null if no signing should be performed.
	 * @param encCert certificate that should be used to encrypt the messages. 
	 * Set this to null if no encryption should be done.
	 */
	public SubMessages(X509Certificate userCert, PrivateKey userKey, X509Certificate encCert){
		
		if(userCert != null && userKey != null){
			this.isSigned = true;
			this.userCert = userCert;
			this.userKey = userKey;
		}
		
		if(encCert != null){
			this.isEncrypted = true;
			this.encCert = encCert;
		}
		
	}
	
	/**
	 * Constructor to use when loading a SubMessage from persisted state
	 */
    public SubMessages(){}
    
    /**
     * Method use by db api to load a persisted submessage
     * @param cACertChain is the CA chain that signed the RA and CAService keystore
     * @param crls could be set to null to disable CRL checking
     */
	void load(String data, PrivateKey userKey, Collection<java.security.cert.Certificate> cACertChain){
		try {		
			submessages.clear();
			java.beans.XMLDecoder decoder = new  java.beans.XMLDecoder(new java.io.ByteArrayInputStream(data.getBytes("UTF8")));
			isSigned = ((Boolean) decoder.readObject()).booleanValue();
			isEncrypted = ((Boolean) decoder.readObject()).booleanValue();
			byte[] messagedata = Base64.decode(((String) decoder.readObject()).getBytes());
			decoder.close();
			
			if(isEncrypted){
				messagedata = ExtRAMsgHelper.decryptData(userKey, messagedata);
			}
			
			if(isSigned){
				ParsedSignatureResult result = ExtRAMsgHelper.verifySignature(cACertChain,messagedata);
				if(!result.isValid()){
					throw new SignatureException("Signature not valid");
				}
				this.signerCert = result.getSignerCert();
				messagedata = result.getContent();
			}
			
			ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(messagedata));
			@SuppressWarnings("unchecked")
            List<HashMap<String, Integer>> savearray = (ArrayList<HashMap<String, Integer>>) ois.readObject(); 
							        	        
	        Iterator<HashMap<String, Integer>> iter = savearray.iterator();
	        while(iter.hasNext()){
	        	HashMap<String, Integer> map = iter.next();
	        	ISubMessage submessage = SubMessageFactory.createInstance(map);
	        	submessage.loadData(map);
	        	submessages.add(submessage);
	        }
	        ois.close();
		}catch (Exception e) {
			log.error("Error reading persistent SubMessages.", e);
		}
	}

	/**
	 * Method used to persist the set of submessages
	 * @return a String representation of the data
	 */
	String save(){
		String retval = null;

		ArrayList<Object> savearray = new ArrayList<Object>();
		
		Iterator<ISubMessage> iter = submessages.iterator();
		while(iter.hasNext()){
		   ISubMessage next = iter.next();
		   savearray.add(next.saveData());
		}
		
		try{
			java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
			ObjectOutputStream oos = new ObjectOutputStream(baos);		
			oos.writeObject(savearray);
			byte[] messagedata = baos.toByteArray();
		
			if(isSigned){
				messagedata = ExtRAMsgHelper.signData(userKey, userCert, messagedata);
			}
			
			if(isEncrypted){
				messagedata = ExtRAMsgHelper.encryptData(encCert,messagedata);
			}
		
			java.io.ByteArrayOutputStream baos2 = new java.io.ByteArrayOutputStream();
			
			java.beans.XMLEncoder encoder = new java.beans.XMLEncoder(baos2);
			encoder.writeObject(Boolean.valueOf(isSigned));
			encoder.writeObject(Boolean.valueOf(isEncrypted));
			encoder.writeObject(new String(Base64.encode(messagedata)));
			encoder.close();
			retval =baos2.toString("UTF8");	
		} catch (Exception e) {
			log.error("Error writing persistent SubMessages.", e);
		}
		
		return retval;
	}
	
	/**
	 * Method to add a submessage to the message sent between RA and CA.
	 */
	public void addSubMessage(ISubMessage submessage){
		submessages.add(submessage);
	}
	
	/**
	 * Method to retreive a collection of submessages.
	 */
	public ArrayList<ISubMessage> getSubMessages(){
		return submessages;
	}
	
	/**
	 * Returns true if this message is signed
	 */
	public boolean isSigned(){
		return isSigned;
	}
	
	/**
	 * Returns true if this message is encrypted
	 */
	public boolean isEncrypted(){
		return isEncrypted;
	}
	
	/**
	 * Returns the certificate of the signer, or null if message isn't signed
	 *
	 */
	public X509Certificate getSignerCert(){
		return signerCert;
	}
}
