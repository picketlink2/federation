package org.picketlink.identity.federation.newmodel.saml.v2.metadata;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.xml.datatype.Duration;
import javax.xml.datatype.XMLGregorianCalendar;

import org.picketlink.identity.xmlsec.w3.xmldsig.SignatureType;


/**
 * <p>Java class for EntityDescriptorType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="EntityDescriptorType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element ref="{http://www.w3.org/2000/09/xmldsig#}Signature" minOccurs="0"/>
 *         &lt;element ref="{urn:oasis:names:tc:SAML:2.0:metadata}Extensions" minOccurs="0"/>
 *         &lt;choice>
 *           &lt;choice maxOccurs="unbounded">
 *             &lt;element ref="{urn:oasis:names:tc:SAML:2.0:metadata}RoleDescriptor"/>
 *             &lt;element ref="{urn:oasis:names:tc:SAML:2.0:metadata}IDPSSODescriptor"/>
 *             &lt;element ref="{urn:oasis:names:tc:SAML:2.0:metadata}SPSSODescriptor"/>
 *             &lt;element ref="{urn:oasis:names:tc:SAML:2.0:metadata}AuthnAuthorityDescriptor"/>
 *             &lt;element ref="{urn:oasis:names:tc:SAML:2.0:metadata}AttributeAuthorityDescriptor"/>
 *             &lt;element ref="{urn:oasis:names:tc:SAML:2.0:metadata}PDPDescriptor"/>
 *           &lt;/choice>
 *           &lt;element ref="{urn:oasis:names:tc:SAML:2.0:metadata}AffiliationDescriptor"/>
 *         &lt;/choice>
 *         &lt;element ref="{urn:oasis:names:tc:SAML:2.0:metadata}Organization" minOccurs="0"/>
 *         &lt;element ref="{urn:oasis:names:tc:SAML:2.0:metadata}ContactPerson" maxOccurs="unbounded" minOccurs="0"/>
 *         &lt;element ref="{urn:oasis:names:tc:SAML:2.0:metadata}AdditionalMetadataLocation" maxOccurs="unbounded" minOccurs="0"/>
 *       &lt;/sequence>
 *       &lt;attribute name="entityID" use="required" type="{urn:oasis:names:tc:SAML:2.0:metadata}entityIDType" />
 *       &lt;attribute name="validUntil" type="{http://www.w3.org/2001/XMLSchema}dateTime" />
 *       &lt;attribute name="cacheDuration" type="{http://www.w3.org/2001/XMLSchema}duration" />
 *       &lt;attribute name="ID" type="{http://www.w3.org/2001/XMLSchema}ID" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
public class EntityDescriptorType extends TypeWithOtherAttributes
{
   public static class EDTChoiceType
   {
      private List<EDTDescriptorChoiceType> descriptors = new ArrayList<EntityDescriptorType.EDTDescriptorChoiceType>();
      private AffiliationDescriptorType affiliationDescriptor;

      public EDTChoiceType(List<EDTDescriptorChoiceType> descriptors)
      {
         this.descriptors = descriptors;
      }
      public EDTChoiceType(AffiliationDescriptorType affiliationDescriptor)
      { 
         this.affiliationDescriptor = affiliationDescriptor;
      }
      public List<EDTDescriptorChoiceType> getDescriptors()
      {
         return Collections.unmodifiableList( descriptors );
      }
      public AffiliationDescriptorType getAffiliationDescriptor()
      {
         return affiliationDescriptor;
      } 
      
      public static EDTChoiceType oneValue( EDTDescriptorChoiceType edt )
      {
         List<EDTDescriptorChoiceType> aList = new ArrayList<EntityDescriptorType.EDTDescriptorChoiceType>();
         aList.add(edt);
         return new EDTChoiceType( aList );
      }
   }

   public static class EDTDescriptorChoiceType
   {
      private RoleDescriptorType roleDescriptor;
      private IDPSSODescriptorType idpDescriptor;
      private SPSSODescriptorType spDescriptor;
      private AuthnAuthorityDescriptorType authnDescriptor;
      private AttributeAuthorityDescriptorType attribDescriptor;
      private PDPDescriptorType pdpDescriptor;
      public EDTDescriptorChoiceType(RoleDescriptorType roleDescriptor)
      { 
         this.roleDescriptor = roleDescriptor;
      }
      public EDTDescriptorChoiceType(IDPSSODescriptorType idpDescriptor)
      {
         super();
         this.idpDescriptor = idpDescriptor;
      }
      public EDTDescriptorChoiceType(SPSSODescriptorType spDescriptor)
      {
         super();
         this.spDescriptor = spDescriptor;
      }
      public EDTDescriptorChoiceType(AuthnAuthorityDescriptorType authnDescriptor)
      {
         super();
         this.authnDescriptor = authnDescriptor;
      }
      public EDTDescriptorChoiceType(AttributeAuthorityDescriptorType attribDescriptor)
      {
         super();
         this.attribDescriptor = attribDescriptor;
      }
      public EDTDescriptorChoiceType(PDPDescriptorType pdpDescriptor)
      {
         super();
         this.pdpDescriptor = pdpDescriptor;
      }
      public RoleDescriptorType getRoleDescriptor()
      {
         return roleDescriptor;
      }
      public IDPSSODescriptorType getIdpDescriptor()
      {
         return idpDescriptor;
      }
      public SPSSODescriptorType getSpDescriptor()
      {
         return spDescriptor;
      }
      public AuthnAuthorityDescriptorType getAuthnDescriptor()
      {
         return authnDescriptor;
      }
      public AttributeAuthorityDescriptorType getAttribDescriptor()
      {
         return attribDescriptor;
      }
      public PDPDescriptorType getPdpDescriptor()
      {
         return pdpDescriptor;
      }  
   }

   protected SignatureType signature;
   protected ExtensionsType extensions;

   protected List<EDTChoiceType> choiceType = new ArrayList<EntityDescriptorType.EDTChoiceType>();

   protected OrganizationType organization;

   protected List<ContactType> contactPerson = new ArrayList<ContactType>();

   protected List<AdditionalMetadataLocationType> additionalMetadataLocation = new ArrayList<AdditionalMetadataLocationType>();

   protected String entityID;

   protected XMLGregorianCalendar validUntil;

   protected Duration cacheDuration;

   protected String id;


   /**
    * Gets the value of the signature property.
    * 
    * @return
    *     possible object is
    *     {@link SignatureType }
    *     
    */
   public SignatureType getSignature() {
      return signature;
   }

   /**
    * Sets the value of the signature property.
    * 
    * @param value
    *     allowed object is
    *     {@link SignatureType }
    *     
    */
   public void setSignature(SignatureType value) {
      this.signature = value;
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

   public List<EDTChoiceType> getChoiceType()
   {
      return Collections.unmodifiableList( choiceType );
   }

   public void addChoiceType(EDTChoiceType choiceType)
   {
      this.choiceType.add( choiceType );
   }

   /**
    * Gets the value of the organization property.
    * 
    * @return
    *     possible object is
    *     {@link OrganizationType }
    *     
    */
   public OrganizationType getOrganization() {
      return organization;
   }

   /**
    * Sets the value of the organization property.
    * 
    * @param value
    *     allowed object is
    *     {@link OrganizationType }
    *     
    */
   public void setOrganization(OrganizationType value) {
      this.organization = value;
   }

   /**
    * Gets the value of the contactPerson property.
    * <p>
    * Objects of the following type(s) are allowed in the list
    * {@link ContactType }
    * 
    * 
    */
   public List<ContactType> getContactPerson() 
   {
      return Collections.unmodifiableList( this.contactPerson );
   }

   /**
    * Gets the value of the additionalMetadataLocation property.
    * 
    * <p>
    * This accessor method returns a reference to the live list,
    * not a snapshot. Therefore any modification you make to the
    * returned list will be present inside the JAXB object.
    * This is why there is not a <CODE>set</CODE> method for the additionalMetadataLocation property.
    * 
    * <p>
    * For example, to add a new item, do as follows:
    * <pre>
    *    getAdditionalMetadataLocation().add(newItem);
    * </pre>
    * 
    * 
    * <p>
    * Objects of the following type(s) are allowed in the list
    * {@link AdditionalMetadataLocationType }
    * 
    * 
    */
   public List<AdditionalMetadataLocationType> getAdditionalMetadataLocation() 
   {
      return Collections.unmodifiableList( this.additionalMetadataLocation );
   }

   /**
    * Gets the value of the entityID property.
    * 
    * @return
    *     possible object is
    *     {@link String }
    *     
    */
   public String getEntityID() {
      return entityID;
   }

   /**
    * Sets the value of the entityID property.
    * 
    * @param value
    *     allowed object is
    *     {@link String }
    *     
    */
   public void setEntityID(String value) {
      this.entityID = value;
   }

   /**
    * Gets the value of the validUntil property.
    * 
    * @return
    *     possible object is
    *     {@link XMLGregorianCalendar }
    *     
    */
   public XMLGregorianCalendar getValidUntil() {
      return validUntil;
   }

   /**
    * Sets the value of the validUntil property.
    * 
    * @param value
    *     allowed object is
    *     {@link XMLGregorianCalendar }
    *     
    */
   public void setValidUntil(XMLGregorianCalendar value) {
      this.validUntil = value;
   }

   /**
    * Gets the value of the cacheDuration property.
    * 
    * @return
    *     possible object is
    *     {@link Duration }
    *     
    */
   public Duration getCacheDuration() {
      return cacheDuration;
   }

   /**
    * Sets the value of the cacheDuration property.
    * 
    * @param value
    *     allowed object is
    *     {@link Duration }
    *     
    */
   public void setCacheDuration(Duration value) {
      this.cacheDuration = value;
   }

   /**
    * Gets the value of the id property.
    * 
    * @return
    *     possible object is
    *     {@link String }
    *     
    */
   public String getID() {
      return id;
   }

   /**
    * Sets the value of the id property.
    * 
    * @param value
    *     allowed object is
    *     {@link String }
    *     
    */
   public void setID(String value) {
      this.id = value;
   } 
}