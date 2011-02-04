package org.picketlink.identity.federation.core.config;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List; 


/**
 * 
 * 				The token providers specify the classes that handle the requests for each type of security Token.
 * 				For example, a SAMLTokenProvider may be used to generate SAML token, while a X509TokenProvider
 * 				may be used to generate X.509 tokens (certificates).
 * 			
 * 
 * <p>Java class for TokenProvidersType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="TokenProvidersType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="TokenProvider" type="{urn:picketlink:identity-federation:config:1.0}TokenProviderType" maxOccurs="unbounded"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */ 
public class TokenProvidersType {
 
    protected List<TokenProviderType> tokenProvider = new ArrayList<TokenProviderType>();

    public void add( TokenProviderType tp )
    {
       this.tokenProvider.add(tp);
    }
    
    public void remove( TokenProviderType tp )
    {
       this.tokenProvider.remove(tp);
    }
    
    /**
     * Gets the value of the tokenProvider property.
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link TokenProviderType }
     * 
     * 
     */
    public List<TokenProviderType> getTokenProvider() { 
        return Collections.unmodifiableList( this.tokenProvider );
    }

}
