/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2008, Red Hat Middleware LLC, and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.picketlink.identity.federation.core.parsers;

import java.io.InputStream;
import java.security.AccessController;
import java.security.PrivilegedAction;

import javax.xml.stream.EventFilter;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Characters;
import javax.xml.stream.events.XMLEvent;

import org.picketlink.identity.federation.PicketLinkLogger;
import org.picketlink.identity.federation.PicketLinkLoggerFactory;
import org.picketlink.identity.federation.core.exceptions.ParsingException;
import org.picketlink.identity.federation.core.parsers.util.StaxParserUtil;
import org.picketlink.identity.federation.core.util.SystemPropertiesUtil;
import org.picketlink.identity.federation.web.constants.GeneralConstants;

/**
 * Base class for parsers
 *
 * @author Anil.Saldhana@redhat.com
 * @since Oct 12, 2010
 */
public abstract class AbstractParser implements ParserNamespaceSupport {
    
    protected static final PicketLinkLogger logger = PicketLinkLoggerFactory.getLogger();

    /**
     * Get the JAXP {@link XMLInputFactory}
     * @return
     */
    protected XMLInputFactory getXMLInputFactory() {
        boolean tccl_jaxp = SystemPropertiesUtil.getSystemProperty(GeneralConstants.TCCL_JAXP, "false")
                .equalsIgnoreCase("true");
        ClassLoader prevTCCL = getTCCL();
        try {
            if (tccl_jaxp) {
                setTCCL(getClass().getClassLoader());
            }
            return XMLInputFactory.newInstance();
        } finally {
            if (tccl_jaxp) {
                setTCCL(prevTCCL);
            }
        }

    }
    
    /**
     * Parse an InputStream for payload
     *
     * @param configStream
     * @return
     * @throws {@link IllegalArgumentException}
     * @throws {@link IllegalArgumentException} when the configStream is null
     */
    public Object parse(InputStream configStream) throws ParsingException {
        if (configStream == null)
            throw logger.nullArgumentError("InputStream");

        XMLInputFactory xmlInputFactory = getXMLInputFactory();

        XMLEventReader xmlEventReader = StaxParserUtil.getXMLEventReader(configStream);

        try {
            xmlEventReader = xmlInputFactory.createFilteredReader(xmlEventReader, new EventFilter() {
                public boolean accept(XMLEvent xmlEvent) {
                    // We are going to disregard characters that are new line and whitespace
                    if (xmlEvent.isCharacters()) {
                        Characters chars = xmlEvent.asCharacters();
                        String data = chars.getData();
                        data = valid(data) ? data.trim() : null;
                        return valid(data);
                    } else {
                        return xmlEvent.isStartElement() || xmlEvent.isEndElement();
                    }
                }

                private boolean valid(String str) {
                    return str != null && str.length() > 0;
                }
            });
        } catch (XMLStreamException e) {
            throw logger.parserException(e);
        }

        return parse(xmlEventReader);
    }

    private ClassLoader getTCCL(){
        if(System.getSecurityManager() != null){
            return AccessController.doPrivileged(new PrivilegedAction<ClassLoader>() {
                public ClassLoader run() {
                    return Thread.currentThread().getContextClassLoader();
                }
            });
        } else {
            return Thread.currentThread().getContextClassLoader();
        }
    }

    private void setTCCL(final ClassLoader paramCl){
        if(System.getSecurityManager() != null){
            AccessController.doPrivileged(new PrivilegedAction<Void>() {
                public Void run() {
                    Thread.currentThread().setContextClassLoader(paramCl);
                    return null;
                }
            });
        } else {
            Thread.currentThread().setContextClassLoader(paramCl);
        }
    }
}