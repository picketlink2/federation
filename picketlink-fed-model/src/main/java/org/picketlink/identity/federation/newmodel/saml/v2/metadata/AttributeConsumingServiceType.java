package org.picketlink.identity.federation.newmodel.saml.v2.metadata;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;


/**
 * <p>Java class for AttributeConsumingServiceType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="AttributeConsumingServiceType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element ref="{urn:oasis:names:tc:SAML:2.0:metadata}ServiceName" maxOccurs="unbounded"/>
 *         &lt;element ref="{urn:oasis:names:tc:SAML:2.0:metadata}ServiceDescription" maxOccurs="unbounded" minOccurs="0"/>
 *         &lt;element ref="{urn:oasis:names:tc:SAML:2.0:metadata}RequestedAttribute" maxOccurs="unbounded"/>
 *       &lt;/sequence>
 *       &lt;attribute name="index" use="required" type="{http://www.w3.org/2001/XMLSchema}unsignedShort" />
 *       &lt;attribute name="isDefault" type="{http://www.w3.org/2001/XMLSchema}boolean" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */ 
public class AttributeConsumingServiceType 
{
   protected List<LocalizedNameType> serviceName = new ArrayList<LocalizedNameType>();

   protected List<LocalizedNameType> serviceDescription = new ArrayList<LocalizedNameType>();

   protected List<RequestedAttributeType> requestedAttribute = new ArrayList<RequestedAttributeType>();

   protected int index;

   protected Boolean isDefault;



   public AttributeConsumingServiceType(int index)
   { 
      this.index = index;
   }

   /**
    * Gets the value of the serviceName property.
    * <p>
    * Objects of the following type(s) are allowed in the list
    * {@link LocalizedNameType }
    * 
    * 
    */
   public List<LocalizedNameType> getServiceName() 
   {
      return Collections.unmodifiableList( this.serviceName );
   }

   /**
    * Gets the value of the serviceDescription property.
    * <p>
    * Objects of the following type(s) are allowed in the list
    * {@link LocalizedNameType }
    * 
    * 
    */
   public List<LocalizedNameType> getServiceDescription() 
   {
      return Collections.unmodifiableList( this.serviceDescription );
   }

   /**
    * Gets the value of the requestedAttribute property.
    * <p>
    * Objects of the following type(s) are allowed in the list
    * {@link RequestedAttributeType }
    * 
    * 
    */
   public List<RequestedAttributeType> getRequestedAttribute() 
   {
      return Collections.unmodifiableList( this.requestedAttribute );
   }

   /**
    * Gets the value of the index property.
    * 
    */
   public int getIndex() 
   {
      return index;
   }

   /**
    * Gets the value of the isDefault property.
    * 
    * @return
    *     possible object is
    *     {@link Boolean }
    *     
    */
   public Boolean isIsDefault() 
   {
      return isDefault;
   }

   /**
    * Sets the value of the isDefault property.
    * 
    * @param value
    *     allowed object is
    *     {@link Boolean }
    *     
    */
   public void setIsDefault(Boolean value) 
   {
      this.isDefault = value;
   }
}