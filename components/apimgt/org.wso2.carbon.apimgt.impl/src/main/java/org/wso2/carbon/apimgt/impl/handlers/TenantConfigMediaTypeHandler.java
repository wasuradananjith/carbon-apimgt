/*
 *  Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.wso2.carbon.apimgt.impl.handlers;

import org.eclipse.wst.validation.internal.ResourceConstants;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.caching.CacheProvider;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.registry.core.jdbc.handlers.Handler;
import org.wso2.carbon.registry.core.jdbc.handlers.RequestContext;

import javax.cache.Cache;
import javax.cache.CacheManager;
import javax.cache.Caching;

public class TenantConfigMediaTypeHandler extends Handler {

    public void put(RequestContext requestContext) {
        clearConfigCache();
    }

    public void delete(RequestContext requestContext) {
        clearConfigCache();
    }

    private void clearConfigCache() {

        // Clear the necessary caches of the product
        CacheManager apimCacheManager = Caching.getCacheManager(APIConstants.API_MANAGER_CACHE_MANAGER);
        Cache tenantConfigCache = CacheProvider.getTenantConfigCache();
        int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        String cacheName = tenantId + "_" + APIConstants.TENANT_CONFIG_CACHE_NAME;
        // Clear the tenant-config cache of the product
        if (tenantConfigCache.containsKey(cacheName)) {
            tenantConfigCache.remove(cacheName);
        }
        // Clear the REST API Scope cache of the product
        apimCacheManager.getCache(APIConstants.REST_API_SCOPE_CACHE).put(tenantDomain, null);

        // Clear the necessary caches of the extensions
        CacheManager extensionsCacheManager = Caching.getCacheManager(APIConstants.EXTENTIONS_CACHE_MANAGER);
        Cache tenantConfigCacheOfExtensionsCacheManagerTenantConfigCache = extensionsCacheManager.getCache(APIConstants.TENANT_CONFIG_CACHE_NAME);
        // Clear the tenant-config cache of the extensions
        if (tenantConfigCacheOfExtensionsCacheManagerTenantConfigCache.containsKey(cacheName)) {
            tenantConfigCacheOfExtensionsCacheManagerTenantConfigCache.remove(cacheName);
        }
        // Clear the REST API Scope cache of the extensions
        extensionsCacheManager.getCache(APIConstants.REST_API_SCOPE_CACHE).put(tenantDomain, null);
    }
}
