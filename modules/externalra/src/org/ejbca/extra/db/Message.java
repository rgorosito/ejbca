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

import java.io.Serializable;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.Id;
import javax.persistence.Lob;
import javax.persistence.NoResultException;
import javax.persistence.Query;
import javax.persistence.Table;
import javax.persistence.Transient;

/**
 * Message is a JPA entity for storing requests and responses for the External RA
 * 
 * @version $Id$
 */
@Entity
@Table(name="message")
public class Message implements Serializable, Cloneable {

	private static final long serialVersionUID = 1L;

	public static final Integer STATUS_WAITING   = Integer.valueOf(1);
	public static final Integer STATUS_INPROCESS = Integer.valueOf(2);
	public static final Integer STATUS_PROCESSED = Integer.valueOf(3);

	private String uniqueId;
	private String messageid;
	private Integer type;
	private Integer status;
	private long createtime;
	private long modifytime;
	private String message;

    /** default constructor */
    public Message() { }
    
    /** constructor with id */
    public Message(String messageid, Integer type) {
    	setUniqueId(createUniqueIdString(messageid, type)); 
        setMessageid(messageid);
        setType(type);
        long currenttime = new Date().getTime();
        setCreatetime(currenttime);
        setModifytime(currenttime);
        setStatus(Message.STATUS_WAITING);
    }
    
    public void update(SubMessages submessages, Integer status){
    	setSubMessages(submessages);
    	setStatus(status);
    	setModifytime(new Date().getTime());
    }
    
    public static String createUniqueIdString(String messageId, Integer type) {
    	return "" + messageId.hashCode() + type.hashCode();
    }
   
	/** A unique id, messageId.hashCode+type.hashCode, set in constructor */
	@Id
	@Column(name="uniqueId", length=250)
    public String getUniqueId() { return this.uniqueId; }
    private void setUniqueId(String uniqueId) { this.uniqueId = uniqueId; }
    
	/** A unique message id. User defined for example username, scep transactionId or similar */
	@Column(name="messageid")
    public String getMessageid() { return this.messageid; }
    private void setMessageid(String messageid) { this.messageid = messageid; }
    
	/** Type of message one of MessageHome.MESSAGETYPE_XX */
	@Column(name="type", nullable=false)
    public Integer getType() { return this.type; }
    private void setType(Integer type) { this.type = type; }
    
	/** Status of processing. One of Message.STATUS_XX */
	@Column(name="status", nullable=false)
    public Integer getStatus() { return this.status; }
    public void setStatus(Integer status) { this.status = status; }

	/** The time the extra message was stored */
	@Column(name="createtime", nullable=false)
    public long getCreatetime() { return this.createtime; }
    public void setCreatetime(long createtime) { this.createtime = createtime; }

	/** When the extra message was modified */
	@Column(name="modifytime", nullable=false)
    public long getModifytime() { return this.modifytime; }
    public void setModifytime(long modifytime) { this.modifytime = modifytime; }

	/** The message itself, serialized */
	@Column(name="message", length=128*1024)
	@Lob
	public String getMessage() { return this.message; }
	public void setMessage(String message) { this.message = message; }
   
    public boolean equals(Object other) {
        if (this == other) { 
        	return true;
        }
        if ( !(other instanceof Message) ) {
        	return false;
        }
        String id = ((Message)other).getUniqueId();
        if ( (id != null) && (this.uniqueId != null) && id.equals(this.uniqueId) ) {
        	return true;
        }
        if ( (id == null) && (this.uniqueId == null) ) {
        	return true;
        }
        return false;
    }

    public int hashCode() {
        return this.uniqueId.hashCode();
    }
    
    public Message clone() {
    	Message clone = new Message();
    	clone.createtime = createtime;
    	clone.message = message;
    	clone.messageid = messageid;
    	clone.modifytime = modifytime;
    	clone.status = status;
    	clone.uniqueId = uniqueId;
    	return clone;
    }

    /**
     * Method that retrieves the message field.
     * @return a byte[] array containing the message.
     */
    @Transient
    public SubMessages getSubMessages(PrivateKey userKey, Collection<Certificate> cACertChain){
       SubMessages retval = new SubMessages();
       retval.load(getMessage(),  userKey, cACertChain);
       return retval;
    }
    
    /**
     * Method to set the message field, takes a bytearray as input
     * and stores it in database as base64 encoded string.
     */
    public void setSubMessages(SubMessages submessages){
       setMessage(submessages.save());    	
    }
    
	//
	// JPA QL functions. 
	// By keeping them here the ORM mapping is isolated to this file.
	//
    
    public static Message findByUniqueId(EntityManager entityManager, String uniqueId) {
    	return entityManager.find(Message.class, uniqueId);
    }
    
    public static Message getNextWaitingMessage(EntityManager entityManager) {
    	try {
    		Query query = entityManager.createQuery("SELECT a FROM Message a WHERE a.status=:status ORDER BY createtime ASC");
    		query.setParameter("status", STATUS_WAITING);
    		query.setMaxResults(1);
    		return (Message) query.getSingleResult();
    	} catch (NoResultException e) {
    		return null;
    	}
    }
}
