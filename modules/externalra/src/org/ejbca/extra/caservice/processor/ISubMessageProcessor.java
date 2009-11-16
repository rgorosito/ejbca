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
package org.ejbca.extra.caservice.processor;

import org.ejbca.core.model.log.Admin;
import org.ejbca.extra.db.ISubMessage;

/**
 * 
 * @author tomas
 * @version $Id$
 */
public interface ISubMessageProcessor {

    public ISubMessage process(Admin admin, ISubMessage submessage, String errormessage);

}
