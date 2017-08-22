package org.jaaslounge.sso.weblogic.spnego;


import javax.management.*;
import weblogic.management.commo.RequiredModelMBeanWrapper;



/**
 * No description provided.
 * @root JaasLoungeIdentityAsserter
 * @customizer org.jaaslounge.sso.weblogic.spnego.JaasLoungeIdentityAsserterImpl(new RequiredModelMBeanWrapper(this))
 * @dynamic false

 */
@SuppressWarnings("unused")
public interface JaasLoungeIdentityAsserterMBean extends weblogic.management.commo.StandardInterface,weblogic.descriptor.DescriptorBean, weblogic.management.security.authentication.IdentityAsserterMBean, weblogic.management.security.authentication.ServletAuthenticationFilterMBean {
                
        


        /**
         * No description provided.

         * @default "org.jaaslounge.sso.weblogic.IdentityAsserterProviderImpl"
         * @dynamic false
         * @non-configurable
         * @validatePropertyDeclaration false

         * @preserveWhiteSpace
         */
        public java.lang.String getProviderClassName ();


        
        


        /**
         * No description provided.

         * @default "JaasLoungeIdentityAsserter"
         * @dynamic false
         * @non-configurable
         * @validatePropertyDeclaration false

         * @preserveWhiteSpace
         */
        public java.lang.String getDescription ();


        
        


        /**
         * No description provided.

         * @default "1.0"
         * @dynamic false
         * @non-configurable
         * @validatePropertyDeclaration false

         * @preserveWhiteSpace
         */
        public java.lang.String getVersion ();


        
        


        /**
         * No description provided.

         * @default weblogic.security.spi.IdentityAsserter.WWW_AUTHENTICATE_NEGOTIATE,weblogic.security.spi.IdentityAsserter.AUTHORIZATION_NEGOTIATE
         * @dynamic false
         * @non-configurable
         * @validatePropertyDeclaration false

         * @preserveWhiteSpace
         */
        public java.lang.String[] getSupportedTypes ();


        
        


        /**
         * No description provided.

         * @default weblogic.security.spi.IdentityAsserter.WWW_AUTHENTICATE_NEGOTIATE,weblogic.security.spi.IdentityAsserter.AUTHORIZATION_NEGOTIATE
         * @dynamic false

         * @preserveWhiteSpace
         */
        public java.lang.String[] getActiveTypes ();


        /**
         * No description provided.

         * @default weblogic.security.spi.IdentityAsserter.WWW_AUTHENTICATE_NEGOTIATE,weblogic.security.spi.IdentityAsserter.AUTHORIZATION_NEGOTIATE
         * @dynamic false

         * @param newValue - new value for attribute ActiveTypes
         * @exception InvalidAttributeValueException
         * @preserveWhiteSpace
         */
        public void setActiveTypes (java.lang.String[] newValue)
                throws InvalidAttributeValueException;



        
        /**
         * @default "JaasLoungeIdentityAsserter"
         * @dynamic false
         */
         public java.lang.String getName();

          

}
