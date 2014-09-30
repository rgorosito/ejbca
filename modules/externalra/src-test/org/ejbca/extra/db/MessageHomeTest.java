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
package org.ejbca.extra.db;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.security.cert.Certificate;
import java.util.ArrayList;

import javax.persistence.Persistence;

import org.apache.log4j.Logger;
import org.cesecore.util.CryptoProviderTools;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * Makes basic database functionality tests.
 *
 * @version $Id$ 
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class MessageHomeTest {

	private static final Logger log = Logger.getLogger(MessageHomeTest.class);
	
	private static MessageHome msghome = new MessageHome(Persistence.createEntityManagerFactory("external-ra-test-notpolled"), MessageHome.MESSAGETYPE_EXTRA, true);

	@BeforeClass
	public static void beforClass() throws Exception {
		CryptoProviderTools.installBCProvider();
	}

	/**
	 * Test method for 'org.ejbca.extra.db.MessageHome.create(String, String)'
	 */
	@Test
	public void test01Create() throws Exception {
		SubMessages submessages = new SubMessages(null,null,null);
		submessages.addSubMessage(ExtRAMessagesTest.genExtRAPKCS10Request(1, "PKCS10REQ", "PKCS10"));
		submessages.addSubMessage(ExtRAMessagesTest.genExtRAPKCS12Request(2,"PKCS12REQ",false));
		submessages.addSubMessage(ExtRAMessagesTest.genExtRAKeyRecoveryRequest(3,"KEYRECREQ", true,null));
		submessages.addSubMessage(ExtRAMessagesTest.genExtRAPKCS10Response());
		submessages.addSubMessage(ExtRAMessagesTest.genExtRAPKCS12Response());
		
		msghome.create("test1", submessages);
		
		Message msg = msghome.findByMessageId("test1");
		assertTrue(msg.getMessageid().equals("test1"));
		assertTrue(msg.getType().equals(MessageHome.MESSAGETYPE_EXTRA));
		assertTrue(msg.getStatus().equals(Message.STATUS_WAITING));
		ExtRAMessagesTest.checkSubMessages(msg.getSubMessages(null,null).getSubMessages());
		assertTrue(msg.getCreatetime()== msg.getModifytime());
		
		//Thread.sleep(500);
		
		submessages = new SubMessages(null,null,Constants.getUserCert());
		submessages.addSubMessage(ExtRAMessagesTest.genExtRAPKCS10Request(1, "PKCS10REQ", "PKCS10"));
		submessages.addSubMessage(ExtRAMessagesTest.genExtRAPKCS12Request(2,"PKCS12REQ",false));
		submessages.addSubMessage(ExtRAMessagesTest.genExtRAKeyRecoveryRequest(3,"KEYRECREQ", true,null));
		submessages.addSubMessage(ExtRAMessagesTest.genExtRAPKCS10Response());
		submessages.addSubMessage(ExtRAMessagesTest.genExtRAPKCS12Response());
		
		msghome.create("test2",submessages);
		
		msg = msghome.findByMessageId("test2");
		assertTrue(msg.getMessageid().equals("test2"));
		assertTrue(msg.getType().equals(MessageHome.MESSAGETYPE_EXTRA));
		assertTrue(msg.getStatus().equals(Message.STATUS_WAITING));
		ExtRAMessagesTest.checkSubMessages(msg.getSubMessages(Constants.getUserKey(),null).getSubMessages());
		assertTrue(msg.getCreatetime()== msg.getModifytime());   
		
		//Thread.sleep(500);       
		
		submessages = new SubMessages(Constants.getUserCert(),Constants.getUserKey(),null);
		submessages.addSubMessage(ExtRAMessagesTest.genExtRAPKCS10Request(1, "PKCS10REQ", "PKCS10"));
		submessages.addSubMessage(ExtRAMessagesTest.genExtRAPKCS12Request(2,"PKCS12REQ",false));
		submessages.addSubMessage(ExtRAMessagesTest.genExtRAKeyRecoveryRequest(3,"KEYRECREQ", true,null));
		submessages.addSubMessage(ExtRAMessagesTest.genExtRAPKCS10Response());
		submessages.addSubMessage(ExtRAMessagesTest.genExtRAPKCS12Response());
		
		ArrayList<Certificate> cACerts = new ArrayList<Certificate>();
		cACerts.add(Constants.getRootCert());
		cACerts.add(Constants.getIntermediateCert());
		
		msghome.create("test3",submessages);
		
		msg = msghome.findByMessageId("test3");
		assertTrue(msg.getMessageid().equals("test3"));
		assertTrue(msg.getType().equals(MessageHome.MESSAGETYPE_EXTRA));
		assertTrue(msg.getStatus().equals(Message.STATUS_WAITING));
		ExtRAMessagesTest.checkSubMessages(msg.getSubMessages(Constants.getUserKey(),cACerts).getSubMessages());
		assertTrue(msg.getCreatetime()== msg.getModifytime());   
		
		//Thread.sleep(500); 
	}

	/**
	 * Test method for 'org.ejbca.extra.db.MessageHome.update(Message)'
	 */
    @Test
	public void test02Update() {
		Message msg = msghome.findByMessageId("test1");
		assertNotNull(msg);
		
		SubMessages submgs = msg.getSubMessages(null,null);
		assertTrue(submgs.getSubMessages().size() == 5);
		submgs.addSubMessage(ExtRAMessagesTest.genExtRAPKCS10Request(1, "PKCS10REQ", "PKCS10"));
		msg.setSubMessages(submgs);
		
		msghome.update(msg);
		
		msg = msghome.findByMessageId("test1");
		assertNotNull(msg);
		assertTrue(msg.getSubMessages(null,null).getSubMessages().size() == 6);		
		assertTrue(msg.getCreatetime() != msg.getModifytime());
	}

	/**
	 * Test method for 'org.ejbca.extra.db.MessageHome.findByUser(String)'
	 */
    @Test
	public void test03FindByUser() {
	  Message msg = msghome.findByMessageId("test1");
	  assertNotNull(msg);
	  msg = msghome.findByMessageId("test2");
	  assertNotNull(msg);
	  msg = msghome.findByMessageId("test3");
	  assertNotNull(msg); 
	}

	/**
	 * Test method for 'org.ejbca.extra.db.MessageHome.getNextWaitingUser()'
	 */
    @Test
	public void test04GetNextWaitingUser() {
		log.trace(">test04GetNextWaitingUser");
		Message msg = msghome.getNextWaitingMessage();
		
		assertEquals("msghome.getNextWaitingMessage did not return user 'test1'", "test1", msg.getMessageid());
		assertEquals("User 'test1' does not have INPROCESS status", Message.STATUS_INPROCESS, msg.getStatus());
		
		msg = msghome.findByMessageId("test1");
		assertEquals("User 'test1' does not have INPROCESS status", Message.STATUS_INPROCESS, msg.getStatus());
        msg.setStatus(Message.STATUS_PROCESSED);
		
		msg = msghome.getNextWaitingMessage();
		assertEquals("msghome.getNextWaitingMessage did not return user 'test2'", "test2", msg.getMessageid());
		log.trace("<test04GetNextWaitingUser");
	}

	/**
	 * Test method for 'org.ejbca.extra.db.MessageHome.remove(String)'
	 */
    @Test
	public void test05Remove() {
		assertNotNull(msghome.findByMessageId("test1"));
		msghome.remove("test1");
		assertNull(msghome.findByMessageId("test1"));

		assertNotNull(msghome.findByMessageId("test2"));
		msghome.remove("test2");
		assertNull(msghome.findByMessageId("test2"));
		
		assertNotNull(msghome.findByMessageId("test3"));
		msghome.remove("test3");
		assertNull(msghome.findByMessageId("test3"));
		
	}
}
