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

import java.util.Date;

import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * MessageHome is used to manipulate messages (of the Message-class) with the database.
 * Java Persistence API is used for database access.
 * 
 * @see org.ejbca.extra.db.Message
 * @version $Id$
 */
public class MessageHome {

	public static final Integer MESSAGETYPE_EXTRA = Integer.valueOf(1);
	public static final Integer MESSAGETYPE_SCEPRA = Integer.valueOf(2);
	
    private static final Log log = LogFactory.getLog(MessageHome.class);

    private final EntityManagerFactory entityManagerFactory;
    private final Integer type;
    
    private boolean manageTransaction = false;
    
    public MessageHome(EntityManagerFactory entityManagerFactory, Integer type, boolean manageTransaction){
    	this.entityManagerFactory = entityManagerFactory;
    	this.type = type;
    	this.manageTransaction = manageTransaction;
    }
     
	public EntityManager getNewEntityManager() {
		log.trace(">getNewEntityManager");
		EntityManager em = entityManagerFactory.createEntityManager();
		if (manageTransaction) {
			em.getTransaction().begin();
		}
		log.trace("<getNewEntityManager");
		return em;
	}

	public void closeEntityManager(EntityManager em) {
		log.trace(">closeEntityManager");
		if (manageTransaction) {
			em.getTransaction().commit();
		}
		em.close();
		log.trace("<closeEntityManager");
	}

    
    /**
     * Creates a message and store it to database with status waiting.
     * If a message already exists, it will be overwritten.
     * 
     * @param messageId, the unique message id.
     * @param message, the actual message string.
     * @return String, the uniqueId that is the primary key in the database
     */
    
    public String create(String messageId, SubMessages submessages){
    	log.trace(">create : Message, messageId : " + messageId);
    	EntityManager entityManager = getNewEntityManager();
    	Message message;
    	try {
        	message = Message.findByUniqueId(entityManager, Message.createUniqueIdString(messageId, type));
        	if (message != null) {
        		message.update(submessages, Message.STATUS_WAITING);
        	} else {
        		message = new Message(messageId, type);
        		message.setSubMessages(submessages);
        		entityManager.persist(message);
        	}
    	} finally {
        	closeEntityManager(entityManager);
    	}
    	log.trace("<create : Message, messageid : " + messageId);
    	return message.getUniqueId();
    }
   
    /**
     * Method that updates the message data to the database. 
     * 
     * @param msg the message class.
     */
    public void update(Message msg){
      log.trace(">update : Message, Messageid : " + msg.getMessageid());
      EntityManager entityManager = getNewEntityManager();
      try {
    	  msg.setModifytime(new Date().getTime());
    	  entityManager.merge(msg);
      } finally {
    	  closeEntityManager(entityManager);
      }
      log.trace("<update : Message, Messageid : " + msg.getMessageid());
    }
    
    /**
     * Method that removes a message from the database.
     * 
     * @param Messageid, the unique message id.
     */
    public void remove(String messageId){
    	log.trace(">remove : Message, Messageid : " + messageId);
    	EntityManager entityManager = getNewEntityManager();
    	try {
    		Message msg = Message.findByUniqueId(entityManager, Message.createUniqueIdString(messageId, type));
    		if (msg != null) {
    			entityManager.remove(msg);
    		}
    	} finally {
    		closeEntityManager(entityManager);
    	}
    	log.trace("<remove : Message, Messageid : " + messageId);
    }
        
    /**
     * Method that finds the Message for the unique messageid.
     * 
     * This method does not alter the state or lock the message 
     * in any way.
     * 
     * @param messageID the unique message id.
     * @return the Message or null if message doesn't exist in database.
     */
    public Message findByMessageId(String messageId) {
        log.trace(">findByMessageId Message with Messageid: " + messageId);
        Message msg = null;
        EntityManager entityManager = getNewEntityManager();
        try {
        	msg = Message.findByUniqueId(entityManager, Message.createUniqueIdString(messageId, type));
        } finally {
        	closeEntityManager(entityManager);
        }
        log.debug("get successful, " + (msg==null?"no":"") + " instance found");
        return msg;
    }
    
    /**
     * Method that finds the oldest created Message with status waiting.
     * 
     * This method will for concurrency reasons update the message
     * with status STATUS_INPROCESS in one transaction
     * to avoid conflicts.
     * 
     * @return the Message or null if no message is waiting.
     */
    public Message getNextWaitingMessage() {
        log.trace(">getNextWaitingMessage()");
        EntityManager entityManager = getNewEntityManager();
        Message message = null;
        try {
        	message = Message.getNextWaitingMessage(entityManager);
        	if (message != null) {
        		message.setModifytime(new Date().getTime());
        		message.setStatus(Message.STATUS_INPROCESS);
        		//entityManager.flush();
        	}
        } finally {
        	closeEntityManager(entityManager);
        }
        log.trace("<getNextWaitingMessage() : " + (message==null?"No message":"Message " + message.getMessageid()) +" found");
        return message;
    }
 

}
