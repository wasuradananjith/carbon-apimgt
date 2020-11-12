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
import org.wso2.carbon.apimgt.rest.api.publisher.v1.dto.APIProductDTO;
import org.wso2.carbon.apimgt.rest.api.publisher.v1.utils.mappings.APIMappingUtil;
import org.wso2.carbon.registry.api.Registry;
import org.wso2.carbon.registry.api.RegistryException;
import org.wso2.carbon.registry.core.session.UserRegistry;

import java.io.File;
import java.io.IOException;
import java.util.LinkedHashSet;
import java.util.List;

/**
 * This is the util class which consists of all the functions for exporting API Product.
 */
public class ExportAPIProductUtils {

    private static final Log log = LogFactory.getLog(ExportAPIProductUtils.class);

    /**
     * This method retrieves/exports all meta information and registry resources required for an API to
     * recreate.
     *
     * @param apiProvider          API Provider
     * @param apiProductIDToReturn API Product Identifier of the API Product to be returned
     * @param userName             User name of the requester
     * @param exportFormat         Export format of the API Product meta data, could be yaml or json
     * @param isStatusPreserved    Whether API Product status is preserved while export
     * @throws APIImportExportException If an error occurs while retrieving API Product related resources
     * @throws APIManagementException   If an error occurs while retrieving the API Product
     */
    public static File exportApiProduct(APIProvider apiProvider, APIProductIdentifier apiProductIDToReturn, String userName,
                                        ExportFormat exportFormat, boolean isStatusPreserved)
            throws APIImportExportException, APIManagementException {

        UserRegistry registry;
        APIProduct apiProductToReturn = apiProvider.getAPIProduct(apiProductIDToReturn);

        //create temp location for storing API data
        File exportFolder = CommonUtil.createTempDirectory(apiProductIDToReturn);
        String exportAPIProductBasePath = exportFolder.toString();
        String archivePath = exportAPIProductBasePath.concat(File.separator + apiProductIDToReturn.getName() + "-"
                + apiProductIDToReturn.getVersion());
        int tenantId = APIUtil.getTenantId(userName);

        try {
            registry = ServiceReferenceHolder.getInstance().getRegistryService().getGovernanceSystemRegistry(tenantId);
            // Directory creation
            CommonUtil.createDirectory(archivePath);

            // Export thumbnail
            exportAPIProductThumbnail(archivePath, apiProductIDToReturn, registry);

            // Export documents
            List<Documentation> docList = apiProvider.getAllDocumentation(apiProductIDToReturn);
            if (!docList.isEmpty()) {
                exportAPIProductDocumentation(archivePath, docList, apiProductIDToReturn, registry, exportFormat);
            } else if (log.isDebugEnabled()) {
                log.debug("No documentation found for API Product: " + apiProductIDToReturn + ". Skipping API Product documentation export.");
            }

            // Export meta information
            exportAPIProductMetaInformation(archivePath, apiProductToReturn, registry, exportFormat);

            // Export dependent APIs
            exportDependentAPIs(archivePath, apiProductToReturn, exportFormat, apiProvider, userName, isStatusPreserved);

            // Export mTLS authentication related certificates
            if(apiProvider.isClientCertificateBasedAuthenticationConfigured()) {
                if (log.isDebugEnabled()) {
                    log.debug("Mutual SSL enabled. Exporting client certificates.");
                }
                ApiTypeWrapper apiTypeWrapper = new ApiTypeWrapper(apiProductToReturn);
                APIAndAPIProductCommonUtils.exportClientCertificates(archivePath, apiTypeWrapper, tenantId, apiProvider, exportFormat);
            }
            CommonUtil.archiveDirectory(exportAPIProductBasePath);
            FileUtils.deleteQuietly(new File(exportAPIProductBasePath));
            return new File(exportAPIProductBasePath + APIConstants.ZIP_FILE_EXTENSION);
        } catch (APIManagementException e) {
            String errorMessage = "Unable to retrieve artifacts for API Product: " + apiProductIDToReturn.getName()
                    + StringUtils.SPACE + APIConstants.API_DATA_VERSION + " : " + apiProductIDToReturn.getVersion();
            throw new APIImportExportException(errorMessage, e);
        } catch (RegistryException e) {
            String errorMessage = "Error while getting governance registry for tenant: " + tenantId;
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
    private static void exportDependentAPIs(String archivePath, APIProduct apiProductToReturn, ExportFormat exportFormat,
                                            APIProvider provider, String userName, Boolean isStatusPreserved)
            throws APIImportExportException, APIManagementException {
        String apisDirectoryPath = archivePath + File.separator + APIImportExportConstants.APIS_DIRECTORY;
        CommonUtil.createDirectory(apisDirectoryPath);

        List<APIProductResource> apiProductResources = apiProductToReturn.getProductResources();
        for (APIProductResource apiProductResource : apiProductResources) {
            APIIdentifier apiIdentifier = apiProductResource.getApiIdentifier();
            File dependentAPI = ExportApiUtils.exportApi(provider, apiIdentifier, userName, exportFormat,
                    isStatusPreserved);
            CommonUtil.extractArchive(dependentAPI, apisDirectoryPath);
        }
    }

    /**
     * Retrieve thumbnail image for the exporting API Product and store it in the archive directory.
     *
     * @param apiProductIdentifier  ID of the requesting API Product
     * @param registry              Current tenant registry
     * @throws APIImportExportException If an error occurs while retrieving image from the registry or
     *                                  storing in the archive directory
     */
    private static void exportAPIProductThumbnail(String archivePath, APIProductIdentifier apiProductIdentifier, Registry registry)
            throws APIImportExportException {
        APIAndAPIProductCommonUtils.exportAPIOrAPIProductThumbnail(archivePath, apiProductIdentifier, registry);
    }

    /**
     * Retrieve documentation for the exporting API Product and store it in the archive directory.
     * FILE, INLINE, MARKDOWN and URL documentations are handled.
     *
     * @param apiProductIdentifier  ID of the requesting API Product
     * @param registry              Current tenant registry
     * @param docList               Documentation list of the exporting API Product
     * @param exportFormat          Format for export
     * @throws APIImportExportException If an error occurs while retrieving documents from the
     *                                  registry or storing in the archive directory
     */
    private static void exportAPIProductDocumentation(String archivePath, List<Documentation> docList,
                                               APIProductIdentifier apiProductIdentifier, Registry registry, ExportFormat exportFormat)
            throws APIImportExportException {
        APIAndAPIProductCommonUtils.exportAPIOrAPIProductDocumentation(archivePath, docList, apiProductIdentifier, registry, exportFormat);
    }

    /**
     * Retrieve meta information of the API Product to export.
     * URL template information are stored in swagger.json definition while rest of the required
     * data are in api.json
     *
     * @param apiProductToReturn    API Product to be exported
     * @param registry              Current tenant registry
     * @param exportFormat          Export format of file
     * @throws APIImportExportException If an error occurs while exporting meta information
     * @throws APIManagementException If an error occurs while removing unnecessary data from exported API Product
     *                                or while retrieving Swagger definition for API Product
     */
    private static void exportAPIProductMetaInformation(String archivePath, APIProduct apiProductToReturn,
                                                        Registry registry, ExportFormat exportFormat)
            throws APIImportExportException, APIManagementException {

        CommonUtil.createDirectory(archivePath + File.separator + APIImportExportConstants.META_INFO_DIRECTORY);
        // Remove unnecessary data from exported API Product
        cleanApiProductDataToExport(apiProductToReturn);

        try {
            Gson gson = new GsonBuilder().setPrettyPrinting().create();

            // Swagger.json contains complete details about scopes. Therefore scope details and uri templates
            // are removed from api.json.
            apiProductToReturn.setScopes(new LinkedHashSet<>());

            String swaggerDefinition = OASParserUtil.getAPIDefinition(apiProductToReturn.getId(), registry);
            JsonParser parser = new JsonParser();
            JsonObject json = parser.parse(swaggerDefinition).getAsJsonObject();
            String formattedSwaggerJson = gson.toJson(json);
            switch (exportFormat) {
                case YAML:
                    String swaggerInYaml = CommonUtil.jsonToYaml(formattedSwaggerJson);
                    CommonUtil.writeFile(archivePath + APIImportExportConstants.YAML_SWAGGER_DEFINITION_LOCATION,
                            swaggerInYaml);
                    break;
                case JSON:
                    CommonUtil.writeFile(archivePath + APIImportExportConstants.JSON_SWAGGER_DEFINITION_LOCATION,
                            formattedSwaggerJson);
            }

            if (log.isDebugEnabled()) {
                log.debug("Meta information retrieved successfully for API Product: " + apiProductToReturn.getId().getName()
                        + StringUtils.SPACE + APIConstants.API_DATA_VERSION + ": " + apiProductToReturn.getId().getVersion());
            }

            APIProductDTO apiProductDTO = APIMappingUtil.fromAPIProducttoDTO(apiProductToReturn);
            JsonObject apiProductJsonObject = APIAndAPIProductCommonUtils.addTypeAndVersionToFile(
                    APIImportExportConstants.TYPE_API, APIImportExportConstants.APIM_VERSION, gson.toJsonTree(apiProductDTO));
            String apiProductInJson = gson.toJson(apiProductJsonObject);
            switch (exportFormat) {
                case JSON:
                    CommonUtil.writeFile(archivePath + APIImportExportConstants.JSON_API_FILE_LOCATION, apiProductInJson);
                    break;
                case YAML:
                    String apiInYaml = CommonUtil.jsonToYaml(apiProductInJson);
                    CommonUtil.writeFile(archivePath + APIImportExportConstants.YAML_API_FILE_LOCATION, apiInYaml);
                    break;
            }
        } catch (APIManagementException e) {
            String errorMessage = "Error while retrieving Swagger definition for API Product: "
                    + apiProductToReturn.getId().getName() + StringUtils.SPACE + APIConstants.API_DATA_VERSION + ": "
                    + apiProductToReturn.getId().getVersion();
            throw new APIImportExportException(errorMessage, e);
        } catch (IOException e) {
            String errorMessage = "Error while saving as YAML for API Product: " + apiProductToReturn.getId().getName()
                    + StringUtils.SPACE + APIConstants.API_DATA_VERSION + ": " + apiProductToReturn.getId().getVersion();
            throw new APIImportExportException(errorMessage, e);
        }
    }

    /**
     * Clean API Product by removing unnecessary details.
     *
     * @param apiProduct API Product to be exported
     */
    private static void cleanApiProductDataToExport(APIProduct apiProduct) {
        // Thumbnail will be set according to the importing environment. Therefore current URL is removed
        apiProduct.setThumbnailUrl(null);
    }
}
