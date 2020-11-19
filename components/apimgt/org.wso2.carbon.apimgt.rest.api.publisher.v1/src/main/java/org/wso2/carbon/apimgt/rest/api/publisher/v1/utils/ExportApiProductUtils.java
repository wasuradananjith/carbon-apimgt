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

package org.wso2.carbon.apimgt.rest.api.publisher.v1.utils;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.APIProvider;
import org.wso2.carbon.apimgt.api.model.*;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.definitions.OASParserUtil;
import org.wso2.carbon.apimgt.impl.importexport.APIImportExportConstants;
import org.wso2.carbon.apimgt.impl.importexport.APIImportExportException;
import org.wso2.carbon.apimgt.impl.importexport.ExportFormat;
import org.wso2.carbon.apimgt.impl.importexport.utils.CommonUtil;
import org.wso2.carbon.apimgt.impl.internal.ServiceReferenceHolder;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;
import org.wso2.carbon.apimgt.rest.api.publisher.v1.dto.APIDTO;
import org.wso2.carbon.apimgt.rest.api.publisher.v1.dto.APIProductDTO;
import org.wso2.carbon.apimgt.rest.api.publisher.v1.utils.mappings.APIMappingUtil;
import org.wso2.carbon.registry.api.Registry;
import org.wso2.carbon.registry.api.RegistryException;
import org.wso2.carbon.registry.core.session.UserRegistry;

import java.io.File;
import java.io.IOException;
import java.util.LinkedHashSet;
import java.util.List;

public class ExportApiProductUtils {

    private static final Log log = LogFactory.getLog(ExportApiProductUtils.class);

    /**
     * Retrieve thumbnail image for the exporting API Product and store it in the archive directory.
     *
     * @param apiProductIdentifier  ID of the requesting API Product
     * @param registry              Current tenant registry
     * @throws APIImportExportException If an error occurs while retrieving image from the registry or
     *                                  storing in the archive directory
     */
    public static void exportAPIProductThumbnail(String archivePath, APIProductIdentifier apiProductIdentifier,
                                                 Registry registry)
            throws APIImportExportException {
        APIAndAPIProductCommonUtils.exportAPIOrAPIProductThumbnail(archivePath, apiProductIdentifier, registry);
    }

    /**
     * Retrieve documentation for the exporting API Product and store it in the archive directory.
     * FILE, INLINE, MARKDOWN and URL documentations are handled.
     *
     * @param archivePath   File path to the documents to be exported
     * @param apiProductIdentifier  ID of the requesting API Product
     * @param registry              Current tenant registry
     * @param exportFormat          Format for export
     * @param apiProvider   API Provider
     * @throws APIImportExportException If an error occurs while retrieving documents from the
     *                                  registry or storing in the archive directory
     * @throws APIManagementException If an error occurs while retrieving document details
     */
    public static void exportAPIProductDocumentation(String archivePath, APIProductIdentifier apiProductIdentifier,
                                                     Registry registry, ExportFormat exportFormat, APIProvider apiProvider)
            throws APIImportExportException, APIManagementException {
        APIAndAPIProductCommonUtils.exportAPIOrAPIProductDocumentation(archivePath, apiProductIdentifier, registry,
                exportFormat, apiProvider);
    }

    /**
     * Retrieve meta information of the API Product to export.
     * URL template information are stored in swagger.json definition while rest of the required
     * data are in api.json
     *
     * @param archivePath    Folder path to export meta information
     * @param apiProductDtoToReturn APIProductDTO to be exported
     * @param exportFormat   Export format of file
     * @param apiProvider    API Provider
     * @param userName       Username
     * @throws APIImportExportException If an error occurs while exporting meta information
     */
    public static void exportAPIProductMetaInformation(String archivePath, APIProductDTO apiProductDtoToReturn,
                                                       ExportFormat exportFormat, APIProvider apiProvider,
                                                       String userName)
            throws APIImportExportException {

        CommonUtil.createDirectory(archivePath + File.separator + APIImportExportConstants.META_INFO_DIRECTORY);

        try {
            Gson gson = new GsonBuilder().setPrettyPrinting().create();

            String formattedSwaggerJson = apiProvider.getAPIDefinitionOfAPIProduct(
                    APIMappingUtil.fromDTOtoAPIProduct(apiProductDtoToReturn, userName));
            APIAndAPIProductCommonUtils.writeToYamlOrJson(archivePath +
                    APIImportExportConstants.SWAGGER_DEFINITION_LOCATION, exportFormat, formattedSwaggerJson);

            if (log.isDebugEnabled()) {
                log.debug("Meta information retrieved successfully for API Product: " + apiProductDtoToReturn.getName());
            }

            JsonObject apiProductJsonObject = APIAndAPIProductCommonUtils.addTypeAndVersionToFile(
                    APIImportExportConstants.TYPE_API, APIImportExportConstants.APIM_VERSION,
                    gson.toJsonTree(apiProductDtoToReturn));
            String apiProductInJson = gson.toJson(apiProductJsonObject);
            APIAndAPIProductCommonUtils.writeToYamlOrJson(archivePath +
                    APIImportExportConstants.API_FILE_LOCATION, exportFormat, apiProductInJson);
        } catch (APIManagementException e) {
            String errorMessage = "Error while retrieving Swagger definition for API Product: "
                    + apiProductDtoToReturn.getName();
            throw new APIImportExportException(errorMessage, e);
        } catch (IOException e) {
            String errorMessage = "Error while saving as YAML for API Product: " + apiProductDtoToReturn.getName();
            throw new APIImportExportException(errorMessage, e);
        }
    }

    /**
     * Export dependent APIs by checking the resources of the API Product.
     *
     * @param archivePath               Temp location to save the API artifacts
     * @param apiProductToReturn        API Product which the resources should be considered
     * @param userName                  User name of the requester
     * @param provider                  API Product Provider
     * @param exportFormat              Export format of the API meta data, could be yaml or json
     * @param isStatusPreserved         Whether API status is preserved while export
     * @throws APIImportExportException If an error occurs while retrieving API related resources
     */
    public static void exportDependentAPIs(String archivePath, APIProduct apiProductToReturn, ExportFormat exportFormat,
                                           APIProvider provider, String userName, Boolean isStatusPreserved)
            throws APIImportExportException, APIManagementException {
        String apisDirectoryPath = archivePath + File.separator + APIImportExportConstants.APIS_DIRECTORY;
        CommonUtil.createDirectory(apisDirectoryPath);

        List<APIProductResource> apiProductResources = apiProductToReturn.getProductResources();
        for (APIProductResource apiProductResource : apiProductResources) {
            APIIdentifier apiIdentifier = apiProductResource.getApiIdentifier();
            APIDTO apiDtoToReturn = APIMappingUtil.fromAPItoDTO(provider.getAPI(apiIdentifier));
            File dependentAPI = ExportApiUtils.exportApi(provider, apiIdentifier,apiDtoToReturn, userName, exportFormat,
                    isStatusPreserved);
            CommonUtil.extractArchive(dependentAPI, apisDirectoryPath);
        }
    }
}
