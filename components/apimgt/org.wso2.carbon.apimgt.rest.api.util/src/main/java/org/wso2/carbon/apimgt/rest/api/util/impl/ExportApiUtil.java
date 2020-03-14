/*
 *  Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.apimgt.rest.api.util.impl;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.APIProvider;
import org.wso2.carbon.apimgt.api.model.APIIdentifier;
import org.wso2.carbon.apimgt.impl.importexport.APIImportExportException;
import org.wso2.carbon.apimgt.impl.importexport.ExportFormat;
import org.wso2.carbon.apimgt.impl.importexport.utils.APIExportUtil;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;
import org.wso2.carbon.apimgt.rest.api.util.RestApiConstants;
import org.wso2.carbon.apimgt.rest.api.util.utils.RestApiUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.ws.rs.core.Response;
import java.io.File;

public class ExportApiUtil {
    private static final Log log = LogFactory.getLog(ExportApiUtil.class);
    /**
     * Exports an API from API Manager for a given API ID. Meta information, API icon, documentation, WSDL
     * and sequences are exported. This service generates a zipped archive which contains all the above mentioned
     * resources for a given API.
     *
     * @param name           Name of the API that needs to be exported
     * @param version        Version of the API that needs to be exported
     * @param providerName   Provider name of the API that needs to be exported
     * @param format         Format of output documents. Can be YAML or JSON
     * @param preserveStatus Preserve API status on export
     * @return Zipped file containing exported API
     */

    public Response exportApiByParams(String name, String version, String providerName, String format, Boolean preserveStatus) {
        ExportFormat exportFormat;
        String userName;
        APIIdentifier apiIdentifier;
        APIProvider apiProvider;
        String apiDomain;
        String apiRequesterDomain;
        File file;
        //If not specified status is preserved by default
        boolean isStatusPreserved = preserveStatus == null || preserveStatus;

        if (name == null || version == null) {
            RestApiUtil.handleBadRequest("'name' or 'version' should not be null", log);
        }

        try {
            //Default export format is YAML
            exportFormat = StringUtils.isNotEmpty(format) ? ExportFormat.valueOf(format.toUpperCase()) :
                    ExportFormat.YAML;

            userName = RestApiUtil.getLoggedInUsername();

            // If the provider name is not given, take the current logged in user's username as the provider name
            if (providerName == null){
                providerName = userName;
            }

            //provider names with @ signs are only accepted
            apiDomain = MultitenantUtils.getTenantDomain(providerName);
            apiRequesterDomain = RestApiUtil.getLoggedInUserTenantDomain();

            if (!StringUtils.equals(apiDomain, apiRequesterDomain)) {
                //not authorized to export requested API
                RestApiUtil.handleAuthorizationFailure(RestApiConstants.RESOURCE_API +
                        " name:" + name + " version:" + version + " provider:" + providerName, log);
            }

            apiIdentifier = new APIIdentifier(APIUtil.replaceEmailDomain(providerName), name, version);
            apiProvider = RestApiUtil.getLoggedInUserProvider();
            // Checking whether the API exists
            if (!apiProvider.isAPIAvailable(apiIdentifier)) {
                String errorMessage = "Error occurred while exporting. API: " + name + " version: " + version
                        + " not found";
                RestApiUtil.handleResourceNotFoundError(errorMessage, log);
            }

            file = APIExportUtil.exportApi(apiProvider, apiIdentifier, userName, exportFormat, preserveStatus);
            return Response.ok(file)
                    .header(RestApiConstants.HEADER_CONTENT_DISPOSITION, "attachment; filename=\""
                            + file.getName() + "\"")
                    .build();
        } catch (APIManagementException | APIImportExportException e) {
            RestApiUtil.handleInternalServerError("Error while exporting " + RestApiConstants.RESOURCE_API, e, log);
        }
        return null;
    }

    /**
     * Exports an API from API Manager for a given API using the ApiId. ID. Meta information, API icon, documentation,
     * WSDL and sequences are exported. This service generates a zipped archive which contains all the above mentioned
     * resources for a given API.
     *
     * @param apiIdentifier
     * @param preserveStatus Preserve API status on export
     * @return Zipped file containing exported API
     */
    public Response exportApiById(APIIdentifier apiIdentifier, Boolean preserveStatus) {
        ExportFormat exportFormat;
        APIProvider apiProvider;
        String userName;
        File file;
        try {
            exportFormat = ExportFormat.YAML;
            apiProvider = RestApiUtil.getLoggedInUserProvider();
            userName = RestApiUtil.getLoggedInUsername();
            file = APIExportUtil.exportApi(apiProvider, apiIdentifier, userName, exportFormat, preserveStatus);
            return Response.ok(file)
                    .header(RestApiConstants.HEADER_CONTENT_DISPOSITION, "attachment; filename=\""
                            + file.getName() + "\"")
                    .build();
        } catch (APIManagementException | APIImportExportException e) {
            RestApiUtil.handleInternalServerError("Error while exporting " + RestApiConstants.RESOURCE_API, e, log);
        }
        return null;
    }
}
