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
package org.picketlink.identity.federation.newmodel.saml.v2.assertion;

import java.io.Serializable;


/**
 * <p>Java class for ActionType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="ActionType">
 *   &lt;simpleContent>
 *     &lt;extension base="&lt;http://www.w3.org/2001/XMLSchema>string">
 *       &lt;attribute name="Namespace" use="required" type="{http://www.w3.org/2001/XMLSchema}anyURI" />
 *     &lt;/extension>
 *   &lt;/simpleContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */ 
public class ActionType implements Serializable {

   private static final long serialVersionUID = 1L;

   protected String value; 
   protected String namespace;

   /**
    * Gets the value of the value property.
    * 
    * @return
    *     possible object is
    *     {@link String }
    *     
    */
   public String getValue() {
      return value;
   }

   /**
    * Sets the value of the value property.
    * 
    * @param value
    *     allowed object is
    *     {@link String }
    *     
    */
   public void setValue(String value) {
      this.value = value;
   }

   /**
    * Gets the value of the namespace property.
    * 
    * @return
    *     possible object is
    *     {@link String }
    *     
    */
   public String getNamespace() {
      return namespace;
   }

   /**
    * Sets the value of the namespace property.
    * 
    * @param value
    *     allowed object is
    *     {@link String }
    *     
    */
   public void setNamespace(String value) {
      this.namespace = value;
   }
}