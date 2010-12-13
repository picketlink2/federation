package org.picketlink.identity.federation.newmodel.saml.v2.metadata;

import java.net.URI;


/**
 * <p>Java class for AdditionalMetadataLocationType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="AdditionalMetadataLocationType">
 *   &lt;simpleContent>
 *     &lt;extension base="&lt;http://www.w3.org/2001/XMLSchema>anyURI">
 *       &lt;attribute name="namespace" use="required" type="{http://www.w3.org/2001/XMLSchema}anyURI" />
 *     &lt;/extension>
 *   &lt;/simpleContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */ 
public class AdditionalMetadataLocationType 
{
   protected URI value;
   protected URI namespace;

   /**
    * Gets the value of the value property.
    * 
    * @return
    *     possible object is
    *     {@link URI }
    *     
    */
   public URI getValue() 
   {
      return value;
   }

   /**
    * Sets the value of the value property.
    * 
    * @param value
    *     allowed object is
    *     {@link URI }
    *     
    */
   public void setValue(URI value) 
   {
      this.value = value;
   }

   /**
    * Gets the value of the namespace property.
    * 
    * @return
    *     possible object is
    *     {@link URI }
    *     
    */
   public URI getNamespace() 
   {
      return namespace;
   }

   /**
    * Sets the value of the namespace property.
    * 
    * @param value
    *     allowed object is
    *     {@link URI }
    *     
    */
   public void setNamespace(URI value) 
   {
      this.namespace = value;
   }
}