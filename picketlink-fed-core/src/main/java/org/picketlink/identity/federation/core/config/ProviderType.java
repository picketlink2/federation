package org.picketlink.identity.federation.core.config;

import javax.xml.crypto.dsig.CanonicalizationMethod;


/**
 * Base Type for IDP and SP
 * 
 * <p>Java class for ProviderType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="ProviderType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="IdentityURL" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *         &lt;element name="Trust" type="{urn:picketlink:identity-federation:config:1.0}TrustType" minOccurs="0"/>
 *         &lt;element name="KeyProvider" type="{urn:picketlink:identity-federation:config:1.0}KeyProviderType" minOccurs="0"/>
 *         &lt;element name="MetaDataProvider" type="{urn:picketlink:identity-federation:config:1.0}MetadataProviderType" minOccurs="0"/>
 *       &lt;/sequence>
 *       &lt;attribute name="ServerEnvironment" default="picketlink">
 *         &lt;simpleType>
 *           &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *             &lt;enumeration value="picketlink"/>
 *             &lt;enumeration value="TOMCAT"/>
 *           &lt;/restriction>
 *         &lt;/simpleType>
 *       &lt;/attribute>
 *       
        &lt;attribute name="CanonicalizationMethod" use="optional" default="http://www.w3.org/2001/10/xml-exc-c14n#WithComments"
                   type="string"/>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */ 
public class ProviderType {

    protected String identityURL;
    protected TrustType trust;
    protected KeyProviderType keyProvider;
    protected MetadataProviderType metaDataProvider;
    protected String serverEnvironment;
    protected String canonicalizationMethod;

    /**
     * Gets the value of the identityURL property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getIdentityURL() {
        return identityURL;
    }

    /**
     * Sets the value of the identityURL property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setIdentityURL(String value) {
        this.identityURL = value;
    }

    /**
     * Gets the value of the trust property.
     * 
     * @return
     *     possible object is
     *     {@link TrustType }
     *     
     */
    public TrustType getTrust() {
        return trust;
    }

    /**
     * Sets the value of the trust property.
     * 
     * @param value
     *     allowed object is
     *     {@link TrustType }
     *     
     */
    public void setTrust(TrustType value) {
        this.trust = value;
    }

    /**
     * Gets the value of the keyProvider property.
     * 
     * @return
     *     possible object is
     *     {@link KeyProviderType }
     *     
     */
    public KeyProviderType getKeyProvider() {
        return keyProvider;
    }

    /**
     * Sets the value of the keyProvider property.
     * 
     * @param value
     *     allowed object is
     *     {@link KeyProviderType }
     *     
     */
    public void setKeyProvider(KeyProviderType value) {
        this.keyProvider = value;
    }

    /**
     * Gets the value of the metaDataProvider property.
     * 
     * @return
     *     possible object is
     *     {@link MetadataProviderType }
     *     
     */
    public MetadataProviderType getMetaDataProvider() {
        return metaDataProvider;
    }

    /**
     * Sets the value of the metaDataProvider property.
     * 
     * @param value
     *     allowed object is
     *     {@link MetadataProviderType }
     *     
     */
    public void setMetaDataProvider(MetadataProviderType value) {
        this.metaDataProvider = value;
    }

    /**
     * Gets the value of the serverEnvironment property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getServerEnvironment() {
        if (serverEnvironment == null) {
            return "picketlink";
        } else {
            return serverEnvironment;
        }
    }

    /**
     * Sets the value of the serverEnvironment property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setServerEnvironment(String value) {
        this.serverEnvironment = value;
    }


    /**
     * Gets the value of the canonicalizationMethod property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
   public String getCanonicalizationMethod()
   {
      if( canonicalizationMethod == null )
         canonicalizationMethod = CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS;
      
      return canonicalizationMethod;
   }

   /**
    * Sets the value of the canonicalizationMethod property.
    * 
    * @param value
    *     allowed object is
    *     {@link String }
    *     
    */
   public void setCanonicalizationMethod(String canonicalizationMethod)
   {
      this.canonicalizationMethod = canonicalizationMethod;
   }

}