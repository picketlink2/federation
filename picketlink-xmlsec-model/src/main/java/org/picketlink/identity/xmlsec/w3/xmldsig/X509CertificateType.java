package org.picketlink.identity.xmlsec.w3.xmldsig;

public class X509CertificateType
{

   private byte[] encodedCertificate;

   public byte[] getEncodedCertificate()
   {
      return this.encodedCertificate;
   }
   
   public void setEncodedCertificate(byte[] encodedCertificate)
   {
      this.encodedCertificate = encodedCertificate;
   }
}
