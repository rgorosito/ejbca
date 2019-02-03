/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.va.publisher;

import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.core.model.ca.publisher.CustomPublisherContainer;
import org.ejbca.core.model.ca.publisher.LegacyValidationAuthorityPublisher;
import org.ejbca.core.model.ca.publisher.ValidationAuthorityPublisher;
import org.ejbca.core.model.ca.publisher.upgrade.BasePublisherConverter;

/**
 * Factory for converting ValidationAuthorityPublishers and LegacyValidationAuthorityPublishers into EnterpriseValidationAuthorityPublishers
 * 
 * @version $Id$
 *
 */
@SuppressWarnings("deprecation")
public class EnterpriseValidationAuthorityPublisherFactoryImpl implements BasePublisherConverter {

    @Override
    public BasePublisher createPublisher(final BasePublisher publisher) {
        if (publisher instanceof ValidationAuthorityPublisher) {
            return new EnterpriseValidationAuthorityPublisher(publisher);
        } else if (publisher instanceof CustomPublisherContainer) {
            CustomPublisherContainer customPublisherContainer = (CustomPublisherContainer) publisher;
            if (customPublisherContainer.getCustomPublisher() instanceof LegacyValidationAuthorityPublisher) {
                return new EnterpriseValidationAuthorityPublisher(customPublisherContainer);
            }
        }
        return null;
    }
}
