/*
 * JBoss, Home of Professional Open Source Copyright 2009, Red Hat Middleware
 * LLC, and individual contributors by the @authors tag. See the copyright.txt
 * in the distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option)
 * any later version.
 *
 * This software is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this software; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA, or see the FSF
 * site: http://www.fsf.org.
 */
package org.picketlink.identity.federation.core.wstrust;

/**
 * Simple factory for creating {@link STSClient}s.
 *
 * @author <a href="mailto:dbevenius@jboss.com">Daniel Bevenius</a>
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 */
public final class STSClientFactory {

    private static final int INITIAL_NUMBER_OF_CLIENTS_IN_POOL = 10;
    private static STSClientFactory INSTANCE = null;
    private static STSClientPool POOL = null;

    private STSClientFactory() {
    }

    public static STSClientFactory getInstance() {
        if (INSTANCE == null) {
            // pooling disabled
            return getInstance(0);
        }
        return INSTANCE;
    }

    public static STSClientFactory getInstance(int maxClientsInPool) {
        if (INSTANCE == null) {
            INSTANCE = new STSClientFactory();
            POOL = STSClientPool.instance(maxClientsInPool);
        }
        return INSTANCE;
    }

    public STSClient create(final STSClientConfig config) {
        return create(INITIAL_NUMBER_OF_CLIENTS_IN_POOL, config);
    }

    public STSClient create(int initialNumberOfClients, final STSClientConfig config) {
        if (POOL.isPoolingDisabled()) {
            return new STSClient(config);
        }
        POOL.initialize(initialNumberOfClients, config);
        return POOL.takeOut(config);
    }

    public STSClient create(int initialNumberOfClients, final STSClientCreationCallBack callBack) {
        if (POOL.isPoolingDisabled()) {
            return callBack.createClient();
        }
        POOL.initialize(initialNumberOfClients, callBack);
        return POOL.takeOut(callBack.getKey());
    }

}