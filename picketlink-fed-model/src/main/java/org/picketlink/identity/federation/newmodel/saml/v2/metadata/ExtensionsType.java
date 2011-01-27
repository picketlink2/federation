package org.picketlink.identity.federation.newmodel.saml.v2.metadata;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.w3c.dom.Element;


/**
 * <p>Java class for ExtensionsType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="ExtensionsType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;any/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
public class ExtensionsType 
{
   protected List<Object> any = new ArrayList<Object>();

   /**
    * Add an object
    * @param obj
    */
   public void addObject( Object obj )
   {
      this.any.add(obj);
   }
   
   /**
    * Remove an object
    * @param obj
    */
   public void removeObject( Object obj )
   {
      this.any.remove(obj);
   }

   /**
    * Gets the value of the any property.
    * <p>
    * Objects of the following type(s) are allowed in the list
    * {@link Element }
    * {@link Object }
    * 
    * 
    */
   public List<Object> getAny() 
   {
      return Collections.unmodifiableList( this.any );
   } 
}