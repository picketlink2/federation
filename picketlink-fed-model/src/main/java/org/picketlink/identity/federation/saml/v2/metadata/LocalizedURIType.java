package org.picketlink.identity.federation.saml.v2.metadata;

import java.net.URI;


/**
 * <p>Java class for localizedURIType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="localizedURIType">
 *   &lt;simpleContent>
 *     &lt;extension base="&lt;http://www.w3.org/2001/XMLSchema>anyURI">
 *       &lt;attribute ref="{http://www.w3.org/XML/1998/namespace}lang use="required""/>
 *     &lt;/extension>
 *   &lt;/simpleContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */ 
public class LocalizedURIType 
{

   protected URI value; 
   protected String lang;

   public LocalizedURIType(String lang)
   { 
      this.lang = lang;
   }

   /**
    * Gets the value of the value property.
    * 
    * @return
    *     possible object is
    *     {@link String }
    *     
    */
   public URI getValue() {
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
   public void setValue( URI value) {
      this.value = value;
   }

   /**
    * Gets the value of the lang property.
    * 
    * @return
    *     possible object is
    *     {@link String }
    *     
    */
   public String getLang() {
      return lang;
   }
}