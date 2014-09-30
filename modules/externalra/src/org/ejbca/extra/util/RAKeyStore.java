/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.extra.util;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import org.cesecore.util.CryptoProviderTools;

/**
 * Simple utility class that reads a P12 Keystore from file.
 * @author Philip Vendil
 * $Id$
 */
public class RAKeyStore {
	
	private KeyStore keystore = null;
	private String alias = null;
	
	public RAKeyStore(String keystorepath, String password) throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException{
		CryptoProviderTools.installBCProviderIfNotAvailable();
		keystore = KeyStore.getInstance("PKCS12", "BC");
        InputStream in = null;
        try {
            in = new FileInputStream(keystorepath);
            keystore.load(in, password.toCharArray());            
        } finally {
            if (in != null) {
                in.close();
            }
        }
        
	}
	
	public KeyStore getKeyStore(){
		return keystore;
	}
	
	/**
	 * Returns the first found alias for a certificate that is not a CA in keystore.
	 * @return keystore alias
	 * @throws KeyStoreException 
	 */
	public String getAlias() throws KeyStoreException {
		if(alias == null){		
			Enumeration<String> enumeration = keystore.aliases();
			while(enumeration.hasMoreElements()){
				alias = (String) enumeration.nextElement();
				X509Certificate cert = (X509Certificate) keystore.getCertificate(alias);
				if(cert.getBasicConstraints() == -1){
					break;
				}
			}
		}
		
	  return alias;	
	}

}
