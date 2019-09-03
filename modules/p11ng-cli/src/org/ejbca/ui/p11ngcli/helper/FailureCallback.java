/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.p11ngcli.helper;

/**
 * 
 * @version $Id$
 *
 */
public interface FailureCallback {
    /**
     * Called from different threads when a failure has happened.
     * @param thread The source thread of the failure
     * @param message A descriptive message of the failure
     * @throws Exception 
     */
    void failed(OperationsThread thread, String message) throws Exception;
}
