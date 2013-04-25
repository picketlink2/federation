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
package org.picketlink.identity.federation.web.util;

import static org.picketlink.identity.federation.core.util.StringUtil.isNotNull;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;

import javax.servlet.http.HttpServletResponse;

import org.picketlink.identity.federation.PicketLinkLogger;
import org.picketlink.identity.federation.PicketLinkLoggerFactory;
import org.picketlink.identity.federation.core.saml.v2.holders.DestinationInfoHolder;
import org.picketlink.identity.federation.core.util.Base64;
import org.picketlink.identity.federation.web.constants.GeneralConstants;

/**
 * Utility for the HTTP/Post binding
 *
 * @author Anil.Saldhana@redhat.com
 * @since May 22, 2009
 */
public class PostBindingUtil {
    
    private static final PicketLinkLogger logger = PicketLinkLoggerFactory.getLogger();
    
    /**
     * Apply base64 encoding on the message
     *
     * @param stringToEncode
     * @return
     */
    public static String base64Encode(String stringToEncode) throws IOException {
        return Base64.encodeBytes(stringToEncode.getBytes("UTF-8"), Base64.DONT_BREAK_LINES);
    }

    /**
     * Apply base64 decoding on the message and return the byte array
     *
     * @param encodedString
     * @return
     */
    public static byte[] base64Decode(String encodedString) {
        if (encodedString == null)
            throw logger.nullArgumentError("encodedString");

        return Base64.decode(encodedString);
    }

    /**
     * Apply base64 decoding on the message and return the stream
     *
     * @param encodedString
     * @return
     */
    public static InputStream base64DecodeAsStream(String encodedString) {
        if (encodedString == null)
            throw logger.nullArgumentError("encodedString");

        return new ByteArrayInputStream(base64Decode(encodedString));
    }

    /**
     * Send the response to the redirected destination while adding the character encoding of "UTF-8" as well as adding headers
     * for cache-control and Pragma
     *
     * @param destination Destination URI where the response needs to redirect
     * @param response HttpServletResponse
     * @throws IOException
     */
    public static void sendPost(DestinationInfoHolder holder, HttpServletResponse response, boolean request) throws IOException {
        String key = request ? GeneralConstants.SAML_REQUEST_KEY : GeneralConstants.SAML_RESPONSE_KEY;

        String relayState = holder.getRelayState();
        String destination = holder.getDestination();
        String samlMessage = holder.getSamlMessage();

        if (destination == null)
            throw logger.nullValueError("Destination is null");

        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        common(holder.getDestination(), response);
        StringBuilder builder = new StringBuilder();

        builder.append("<html>");
        builder.append("<head>");
        if (request)
            builder.append("<title>HTTP Post Binding (Request)</title>");
        else
            builder.append("<title>HTTP Post Binding Response (Response)</title>");

        builder.append("</head>");
        builder.append("<body onload=\"document.forms[0].submit()\">");

        builder.append("<form method=\"POST\" action=\"" + destination + "\">");
        builder.append("<input type=\"HIDDEN\" name=\"" + key + "\"" + " value=\"" + samlMessage + "\"/>");
        if (isNotNull(relayState)) {
            builder.append("<input type=\"HIDDEN\" name=\"RelayState\" " + "value=\"" + relayState + "\"/>");
        }
        builder.append("</form></body></html>");

        String str = builder.toString();
        logger.trace(str);
        out.println(str);
        out.close();
    }

    private static void common(String destination, HttpServletResponse response) {
        response.setCharacterEncoding("UTF-8");
        response.setHeader("Pragma", "no-cache");
        response.setHeader("Cache-Control", "no-cache, no-store");
    }
}