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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.beans.XMLDecoder;
import java.io.ByteArrayInputStream;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.Base64GetHashMap;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.publisher.PublisherData;
import org.ejbca.core.ejb.ca.publisher.PublisherProxySessionRemote;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionRemote;
import org.ejbca.core.ejb.upgrade.UpgradeSessionRemote;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.core.model.ca.publisher.CustomPublisherContainer;
import org.ejbca.core.model.ca.publisher.LegacyValidationAuthorityPublisher;
import org.ejbca.core.model.ca.publisher.PublisherConst;
import org.ejbca.core.model.ca.publisher.PublisherExistsException;
import org.ejbca.core.model.ca.publisher.ValidationAuthorityPublisher;
import org.junit.Test;

/**
 * Unit  and system tests for upgrading publishers
 * 
 * @version $Id: UpgradePublisherTest.java 25263 2017-02-14 15:51:48Z jeklund $
 *
 */
@SuppressWarnings("deprecation")
public class UpgradePublisherTest {

    private static final Logger log = Logger.getLogger(UpgradePublisherTest.class);

    private static final AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken("UpgradePublisherTest");

    private final PublisherProxySessionRemote publisherProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherProxySessionRemote.class,
            EjbRemoteHelper.MODULE_TEST);
    private final PublisherSessionRemote publisherSession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherSessionRemote.class);
    private final UpgradeSessionRemote upgradeSession = EjbRemoteHelper.INSTANCE.getRemoteSession(UpgradeSessionRemote.class);

    /**
     * Tests the conversion of the old style VA publisher to the replacement placeholder object, strict unit test
     * 
     * @throws PublisherExistsException
     * @throws AuthorizationDeniedException
     */
    @Test
    public void testLegacyValidationAuthorityPublisherConversion() throws PublisherExistsException, AuthorizationDeniedException {
        final String publisherName = "testUpgradeConversion";
        final String dataSource = "foo_datasource";
        final String description = "foo_description";
        ValidationAuthorityPublisher oldStylePublisher = new ValidationAuthorityPublisher();
        oldStylePublisher.setDataSource(dataSource);
        oldStylePublisher.setDescription(description);
        oldStylePublisher.setName(publisherName);
        oldStylePublisher.setStoreCert(false);
        oldStylePublisher.setStoreCRL(false);
        PublisherData publisherData = new PublisherData(4711, publisherName, oldStylePublisher);
        XMLDecoder decoder;
        try {
            decoder = new XMLDecoder(new ByteArrayInputStream(publisherData.getData().getBytes("UTF8")));
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException(e);
        }
        HashMap<?, ?> h = (HashMap<?, ?>) decoder.readObject();
        decoder.close();
        // Handle Base64 encoded string values
        @SuppressWarnings("unchecked")
        HashMap<Object, Object> data = new Base64GetHashMap(h);
        LegacyValidationAuthorityPublisher newPublisher = new LegacyValidationAuthorityPublisher(data);
        if (PublisherConst.TYPE_VAPUBLISHER == ((Integer) data.get(BasePublisher.TYPE)).intValue()) {
            publisherData.setPublisher(newPublisher);
        }

        try {
            decoder = new XMLDecoder(new ByteArrayInputStream(publisherData.getData().getBytes("UTF8")));
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException(e);
        }
        h = (HashMap<?, ?>) decoder.readObject();
        decoder.close();
        // Handle Base64 encoded string values
        @SuppressWarnings("unchecked")
        HashMap<Object, Object> newData = new Base64GetHashMap(h);

        //Assert that data was retained through the conversion 
        assertEquals("Upgraded publisher was of wrong type.", PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER,
                ((Integer) newData.get(BasePublisher.TYPE)).intValue());
        assertEquals("Datasource name was incorrect.", dataSource, (String) newData.get("dataSource"));
        assertEquals("Description was incorrect.", description, (String) newData.get("description"));
        assertEquals("storeCert was incorrect.", false, (Boolean) newData.get("storeCert"));
        assertEquals("storeCRL was incorrect.", false, (Boolean) newData.get("storeCRL"));
    }

    @Test
    public void testLegacyValidationAuthorityPublisherAdhocUpgrade() throws PublisherExistsException, AuthorizationDeniedException {
        final String publisherName = "testLegacyValidationAuthorityPublisherAdhocUpgrade";
        final String dataSource = "foo_datasource";
        final String description = "foo_description";
        ValidationAuthorityPublisher oldStylePublisher = new ValidationAuthorityPublisher();
        oldStylePublisher.setDataSource(dataSource);
        oldStylePublisher.setDescription(description);
        oldStylePublisher.setName(publisherName);
        oldStylePublisher.setStoreCert(false);
        oldStylePublisher.setStoreCRL(false);
        publisherProxySession.addPublisher(internalAdmin, publisherName, oldStylePublisher);
        try {
            //Perform the upgrade
            publisherProxySession.adhocUpgradeTo6_3_1_1();
            BasePublisher basePublisher = publisherSession.getPublisher(publisherName);
            try {
                LegacyValidationAuthorityPublisher upgradedPublisher = (LegacyValidationAuthorityPublisher) ((CustomPublisherContainer) basePublisher)
                        .getCustomPublisher();
                assertEquals("Description was incorrect.", description, basePublisher.getDescription());
                assertEquals("Datasource name was incorrect.", dataSource, upgradedPublisher.getDataSource());
                assertEquals("storeCert was incorrect.", false, upgradedPublisher.getStoreCert());
                assertEquals("storeCRL was incorrect.", false, upgradedPublisher.getStoreCRL());
                // Verify that changes to the upgraded publisher can be modified
                final String newDescription = "bar_description";
                final String newDataSource = "bar_datasource";
                basePublisher.setDescription(newDescription);
                final String propertydata = "storeCert=true\nstoreCRL=true\ndataSource="+newDataSource;
                ((CustomPublisherContainer)basePublisher).setPropertyData(propertydata);
                publisherSession.changePublisher(internalAdmin, publisherName, basePublisher);
                BasePublisher editedBasePublisher = publisherSession.getPublisher(publisherName);
                LegacyValidationAuthorityPublisher editedUpgradedPublisher = (LegacyValidationAuthorityPublisher) ((CustomPublisherContainer) editedBasePublisher)
                        .getCustomPublisher();
                assertEquals("Description was incorrect.", newDescription, editedBasePublisher.getDescription());
                assertEquals("Datasource name was incorrect.", newDataSource, editedUpgradedPublisher.getDataSource());
                assertEquals("storeCert was incorrect.", true, editedUpgradedPublisher.getStoreCert());
                assertEquals("storeCRL was incorrect.", true, editedUpgradedPublisher.getStoreCRL());
            } catch (ClassCastException e) {
                log.error("Upgraded publisher was not of correct type.", e);
                fail("Upgraded publisher was not of correct type.");
            }

        } finally {
            publisherProxySession.removePublisherInternal(internalAdmin, publisherName);
        }
    }

    /**
     * System test for the EnterpriseValidationAuthorityPublisherFactoryImpl. 
     */
    @Test
    public void testPostMigrateDatabase632() throws PublisherExistsException, AuthorizationDeniedException {
        //Make sure database contains an old publisher
        final String oldPublisherName = "testPostMigrateDatabase632VA1";
        final String dataSource = "foo_datasource";
        final String description = "foo_description";
        ValidationAuthorityPublisher oldStylePublisher = new ValidationAuthorityPublisher();
        oldStylePublisher.setDataSource(dataSource);
        oldStylePublisher.setDescription(description);
        oldStylePublisher.setName(oldPublisherName);
        oldStylePublisher.setStoreCert(false);
        oldStylePublisher.setStoreCRL(true);
        publisherProxySession.addPublisher(internalAdmin, oldPublisherName, oldStylePublisher);
        try {
            upgradeSession.upgrade(null, "6.3.1", true);
            BasePublisher oldBasePublisher = publisherSession.getPublisher(oldPublisherName);
            try {
                EnterpriseValidationAuthorityPublisher upgradedPublisher = (EnterpriseValidationAuthorityPublisher) ((CustomPublisherContainer) oldBasePublisher)
                        .getCustomPublisher();
                assertEquals("Description was incorrect.", description, oldBasePublisher.getDescription());
                assertEquals("Datasource name was incorrect.", dataSource, upgradedPublisher.getDataSource());
                assertEquals("storeCert was incorrect.", false, upgradedPublisher.getStoreCert());
                assertEquals("storeCRL was incorrect.", true, upgradedPublisher.getStoreCRL());
                // Verify that changes to the upgraded publisher can be modified
                final String newDescription = "bar_description";
                oldBasePublisher.setDescription(newDescription);
                publisherSession.changePublisher(internalAdmin, oldPublisherName, oldBasePublisher);
                BasePublisher editedBasePublisher = publisherSession.getPublisher(oldPublisherName);
                assertEquals("Description was incorrect.", newDescription, editedBasePublisher.getDescription());
            } catch (ClassCastException e) {
                log.error("Upgraded publisher was not of correct type.", e);
                fail("Upgraded publisher was not of correct type.");
            }
        } finally {
            publisherProxySession.removePublisherInternal(internalAdmin, oldPublisherName);
        }
    }

    /**
     * System test for the EnterpriseValidationAuthorityPublisherFactoryImpl. 
     */
    @Test
    public void testPostMigrateDatabase632Legacy() throws PublisherExistsException, AuthorizationDeniedException {
        //Make sure database contains an old publisher
        final String dataSource = "foo_datasource";
        final String description = "foo_description";
        //Add a Legacy Publisher to test upgrading from Community to Enterprise
        final String legacyPublisherName = "testPostMigrateDatabase632VA2";
        LegacyValidationAuthorityPublisher legacyValidationAuthorityPublisher = new LegacyValidationAuthorityPublisher();
        legacyValidationAuthorityPublisher.setDataSource(dataSource);
        legacyValidationAuthorityPublisher.setDescription(description);
        legacyValidationAuthorityPublisher.setName(legacyPublisherName);
        legacyValidationAuthorityPublisher.setStoreCert(false);
        legacyValidationAuthorityPublisher.setStoreCRL(true);
        legacyValidationAuthorityPublisher.setOnlyPublishRevoked(true);
        legacyValidationAuthorityPublisher.setOnlyUseQueue(true);
        legacyValidationAuthorityPublisher.setKeepPublishedInQueue(true);
        legacyValidationAuthorityPublisher.setUseQueueForCertificates(true);
        legacyValidationAuthorityPublisher.setUseQueueForCRLs(false);
        publisherProxySession.addPublisher(internalAdmin, legacyPublisherName, legacyValidationAuthorityPublisher);
        try {
            upgradeSession.upgrade(null, "6.3.1", true);
            BasePublisher legacyBasePublisher = publisherSession.getPublisher(legacyPublisherName);
            try {
                EnterpriseValidationAuthorityPublisher upgradedLegacyPublisher = (EnterpriseValidationAuthorityPublisher) ((CustomPublisherContainer) legacyBasePublisher)
                        .getCustomPublisher();
                // Check VA Publisher properties
                assertEquals("Datasource name was incorrect.", dataSource, upgradedLegacyPublisher.getDataSource());
                assertEquals("storeCert was incorrect.", false, upgradedLegacyPublisher.getStoreCert());
                assertEquals("storeCRL was incorrect.", true, upgradedLegacyPublisher.getStoreCRL());
                assertEquals("onlyPublishRevoked was incorrect.", true, upgradedLegacyPublisher.getOnlyPublishRevoked());
                // Check base properties also
                assertEquals("Description was incorrect.", description, legacyBasePublisher.getDescription());
                assertEquals("onlyUseQueue was incorrect.", true, legacyBasePublisher.getOnlyUseQueue());
                assertEquals("keepPublishedInQueue was incorrect.", true, legacyBasePublisher.getKeepPublishedInQueue());
                assertEquals("useQueueForCertificates was incorrect.", true, legacyBasePublisher.getUseQueueForCertificates());
                assertEquals("useQueueForCRLs was incorrect.", false, legacyBasePublisher.getUseQueueForCRLs());
            } catch (ClassCastException e) {
                log.error("Upgraded publisher was not of correct type.", e);
                fail("Upgraded publisher was not of correct type.");
            }
        } finally {
            publisherProxySession.removePublisherInternal(internalAdmin, legacyPublisherName);
        }
    }

}
