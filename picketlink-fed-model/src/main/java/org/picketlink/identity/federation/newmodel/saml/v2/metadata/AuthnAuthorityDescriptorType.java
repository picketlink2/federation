package org.picketlink.identity.federation.newmodel.saml.v2.metadata;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;


/**
 * <p>Java class for AuthnAuthorityDescriptorType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="AuthnAuthorityDescriptorType">
 *   &lt;complexContent>
 *     &lt;extension base="{urn:oasis:names:tc:SAML:2.0:metadata}RoleDescriptorType">
 *       &lt;sequence>
 *         &lt;element ref="{urn:oasis:names:tc:SAML:2.0:metadata}AuthnQueryService" maxOccurs="unbounded"/>
 *         &lt;element ref="{urn:oasis:names:tc:SAML:2.0:metadata}AssertionIDRequestService" maxOccurs="unbounded" minOccurs="0"/>
 *         &lt;element ref="{urn:oasis:names:tc:SAML:2.0:metadata}NameIDFormat" maxOccurs="unbounded" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre> 
 */
public class AuthnAuthorityDescriptorType
extends RoleDescriptorType
{
   protected List<EndpointType> authnQueryService = new ArrayList<EndpointType>(); 
   protected List<EndpointType> assertionIDRequestService = new ArrayList<EndpointType>();
   protected List<String> nameIDFormat = new ArrayList<String>();
   
   public AuthnAuthorityDescriptorType(List<String> protocolSupport)
   {
      super(protocolSupport); 
   }

   public void addAuthnQueryService( EndpointType endpoint )
   {
      this.authnQueryService.add(endpoint);
   }

   public void addAssertionIDRequestService( EndpointType endpoint )
   {
      this.assertionIDRequestService.add(endpoint);
   }

   public void addNameIDFormat( String str )
   {
      this.nameIDFormat.add(str);
   }

   /**
    * Gets the value of the authnQueryService property.
    * <p>
    * Objects of the following type(s) are allowed in the list
    * {@link EndpointType }
    * 
    * 
    */
   public List<EndpointType> getAuthnQueryService() 
   {
      return Collections.unmodifiableList( this.authnQueryService );
   }

   /**
    * Gets the value of the assertionIDRequestService property.
    * <p>
    * Objects of the following type(s) are allowed in the list
    * {@link EndpointType }
    * 
    * 
    */
   public List<EndpointType> getAssertionIDRequestService() 
   {
      return Collections.unmodifiableList( this.assertionIDRequestService );
   }

   /**
    * Gets the value of the nameIDFormat property.
    * <p>
    * Objects of the following type(s) are allowed in the list
    * {@link String }
    * 
    * 
    */
   public List<String> getNameIDFormat() 
   {
      return Collections.unmodifiableList( this.nameIDFormat );
   }
}