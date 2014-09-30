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
 
package org.ejbca.externalra.gui;

import java.util.Locale;

import javax.faces.context.FacesContext;

import com.icesoft.faces.facelets.D2DFaceletViewHandler;

/**
 * @version $Id$
 */
public class LocaleViewHandler extends D2DFaceletViewHandler {
	@Override
    public Locale calculateLocale(FacesContext facesContext) {
        Locale locale = (Locale) facesContext.getExternalContext().getSessionMap().get("HTTP_SESSION_KEY_USER_LOCALE");
        if (locale != null) {
            return locale;
        }
        return super.calculateLocale(facesContext);
    }
}
