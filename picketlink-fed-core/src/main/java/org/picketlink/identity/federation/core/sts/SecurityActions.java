/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2009, Red Hat Middleware LLC, and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors. 
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.picketlink.identity.federation.core.sts;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

/**
 * <p>
 * Utility class that executes actions such as creating a class in privileged blocks.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
class SecurityActions
{

   /**
    * <p>
    * Gets the thread context class loader using a privileged block.
    * </p>
    * 
    * @return a reference to the thread context {@code ClassLoader}.
    */
   static ClassLoader getContextClassLoader()
   {
      return AccessController.doPrivileged(new PrivilegedAction<ClassLoader>()
      {
         public ClassLoader run()
         {
            return Thread.currentThread().getContextClassLoader();
         }
      });
   }

   static ClassLoader getClassLoader(final Class<?> clazz)
   {
      return AccessController.doPrivileged(new PrivilegedAction<ClassLoader>()
      {
         public ClassLoader run()
         {
            return clazz.getClassLoader();
         }
      });
   }

   /**
    * <p>
    * Loads a class using the thread context class loader in a privileged block.
    * </p>
    * 
    * @param name the fully-qualified name of the class to be loaded.
    * @return a reference to the loaded {@code Class}.
    * @throws PrivilegedActionException if an error occurs while loading the class. This exception wraps the real cause
    *             of the error, so classes using this method must perform a {@code getCause()} in order to get a
    *             reference to the root of the error.
    */
   static Class<?> loadClass(final String name) throws PrivilegedActionException
   {
      return AccessController.doPrivileged(new PrivilegedExceptionAction<Class<?>>()
      {
         public Class<?> run() throws PrivilegedActionException
         {
            try
            {
               return getContextClassLoader().loadClass(name);
            }
            catch (Exception e)
            {
               throw new PrivilegedActionException(e);
            }
         }
      });
   }

   /**
    * <p>
    * Creates an instance of the specified class in a privileged block. The class must define a default constructor.
    * </p>
    * 
    * @param className the fully-qualified name of the class to be instantiated.
    * @return a reference to the instantiated {@code Object}.
    * @throws PrivilegedActionException if an error occurs while instantiating the class. This exception wraps the real
    *             cause of the error, so classes using this method must perform a {@code getCause()} in order to get a
    *             reference to the root of the error.
    */
   static Object instantiateClass(final String className) throws PrivilegedActionException
   {
      return AccessController.doPrivileged(new PrivilegedExceptionAction<Object>()
      {
         public Object run() throws Exception
         {
            Class<?> objectClass = loadClass(className);
            return objectClass.newInstance();
         }
      });
   }
}