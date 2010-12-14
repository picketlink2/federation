package org.picketlink.identity.federation.newmodel.saml.v2.metadata;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;


/**
 * <p>Java class for OrganizationType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="OrganizationType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element ref="{urn:oasis:names:tc:SAML:2.0:metadata}Extensions" minOccurs="0"/>
 *         &lt;element ref="{urn:oasis:names:tc:SAML:2.0:metadata}OrganizationName" maxOccurs="unbounded"/>
 *         &lt;element ref="{urn:oasis:names:tc:SAML:2.0:metadata}OrganizationDisplayName" maxOccurs="unbounded"/>
 *         &lt;element ref="{urn:oasis:names:tc:SAML:2.0:metadata}OrganizationURL" maxOccurs="unbounded"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */

public class OrganizationType extends TypeWithOtherAttributes
{

   protected ExtensionsType extensions;
   protected List<LocalizedNameType> organizationName = new ArrayList<LocalizedNameType>();

   protected List<LocalizedNameType> organizationDisplayName = new ArrayList<LocalizedNameType>();

   protected List<LocalizedURIType> organizationURL = new ArrayList<LocalizedURIType>();

   public void addOrganizationName( LocalizedNameType name )
   {
      this.organizationName.add(name);
   }

   public void addOrganizationDisplayName( LocalizedNameType name )
   {
      this.organizationDisplayName.add(name);
   }

   public void addOrganizationURL( LocalizedURIType uri )
   {
      this.organizationURL.add(uri);
   }

   /**
    * Gets the value of the extensions property.
    * 
    * @return
    *     possible object is
    *     {@link ExtensionsType }
    *     
    */
   public ExtensionsType getExtensions() {
      return extensions;
   }

   /**
    * Sets the value of the extensions property.
    * 
    * @param value
    *     allowed object is
    *     {@link ExtensionsType }
    *     
    */
   public void setExtensions(ExtensionsType value) {
      this.extensions = value;
   }

   /**
    * Gets the value of the organizationName property.
    * 
    * <p>
    * Objects of the following type(s) are allowed in the list
    * {@link LocalizedNameType }
    *  
    */
   public List<LocalizedNameType> getOrganizationName() 
   {
      return Collections.unmodifiableList( this.organizationName );
   }

   /**
    * Gets the value of the organizationDisplayName property.
    * 
    * <p>
    * Objects of the following type(s) are allowed in the list
    * {@link LocalizedNameType }
    * 
    * 
    */
   public List<LocalizedNameType> getOrganizationDisplayName() 
   {
      return Collections.unmodifiableList( this.organizationDisplayName );
   }

   /**
    * Gets the value of the organizationURL property.
    * 

    */
   public List<LocalizedURIType> getOrganizationURL() 
   {
      return Collections.unmodifiableList( this.organizationURL );
   }
}