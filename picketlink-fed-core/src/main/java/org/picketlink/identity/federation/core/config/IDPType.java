package org.picketlink.identity.federation.core.config;
 

/**
 * 
 * 				IDP Type defines the configuration for an Identity
 * 				Provider.
 * 			
 * 
 * <p>Java class for IDPType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="IDPType">
 *   &lt;complexContent>
 *     &lt;extension base="{urn:picketlink:identity-federation:config:1.0}ProviderType">
 *       &lt;sequence>
 *         &lt;element name="Encryption" type="{urn:picketlink:identity-federation:config:1.0}EncryptionType" minOccurs="0"/>
 *       &lt;/sequence>
 *       &lt;attribute name="AssertionValidity" type="{http://www.w3.org/2001/XMLSchema}long" default="300000" />
 *       &lt;attribute name="RoleGenerator" type="{http://www.w3.org/2001/XMLSchema}string" default="org.picketlink.identity.federation.bindings.tomcat.TomcatRoleGenerator" />
 *       &lt;attribute name="AttributeManager" type="{http://www.w3.org/2001/XMLSchema}string" default="org.picketlink.identity.federation.bindings.tomcat.TomcatAttributeManager" />
 *       &lt;attribute name="Encrypt" type="{http://www.w3.org/2001/XMLSchema}boolean" default="false" />
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */ 
public class IDPType
    extends ProviderType
{

    protected EncryptionType encryption;
    protected Long assertionValidity;
    protected String roleGenerator;
    protected String attributeManager;
    protected Boolean encrypt;

    /**
     * Gets the value of the encryption property.
     * 
     * @return
     *     possible object is
     *     {@link EncryptionType }
     *     
     */
    public EncryptionType getEncryption() {
        return encryption;
    }

    /**
     * Sets the value of the encryption property.
     * 
     * @param value
     *     allowed object is
     *     {@link EncryptionType }
     *     
     */
    public void setEncryption(EncryptionType value) {
        this.encryption = value;
    }

    /**
     * Gets the value of the assertionValidity property.
     * 
     * @return
     *     possible object is
     *     {@link Long }
     *     
     */
    public long getAssertionValidity() {
        if (assertionValidity == null) {
            return  300000L;
        } else {
            return assertionValidity;
        }
    }

    /**
     * Sets the value of the assertionValidity property.
     * 
     * @param value
     *     allowed object is
     *     {@link Long }
     *     
     */
    public void setAssertionValidity(Long value) {
        this.assertionValidity = value;
    }

    /**
     * Gets the value of the roleGenerator property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getRoleGenerator() {
        if (roleGenerator == null) {
            return "org.picketlink.identity.federation.bindings.tomcat.TomcatRoleGenerator";
        } else {
            return roleGenerator;
        }
    }

    /**
     * Sets the value of the roleGenerator property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setRoleGenerator(String value) {
        this.roleGenerator = value;
    }

    /**
     * Gets the value of the attributeManager property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getAttributeManager() {
        if (attributeManager == null) {
            return "org.picketlink.identity.federation.bindings.tomcat.TomcatAttributeManager";
        } else {
            return attributeManager;
        }
    }

    /**
     * Sets the value of the attributeManager property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setAttributeManager(String value) {
        this.attributeManager = value;
    }

    /**
     * Gets the value of the encrypt property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public boolean isEncrypt() {
        if (encrypt == null) {
            return false;
        } else {
            return encrypt;
        }
    }

    /**
     * Sets the value of the encrypt property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setEncrypt(Boolean value) {
        this.encrypt = value;
    }

}
