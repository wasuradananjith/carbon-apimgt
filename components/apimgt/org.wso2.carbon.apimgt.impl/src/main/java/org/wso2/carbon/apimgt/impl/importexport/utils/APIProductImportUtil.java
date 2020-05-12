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

package org.wso2.carbon.apimgt.impl.importexport.utils;

import com.google.common.collect.Sets;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.apimgt.api.APIDefinition;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.APIMgtAuthorizationFailedException;
import org.wso2.carbon.apimgt.api.APIMgtResourceAlreadyExistsException;
import org.wso2.carbon.apimgt.api.APIMgtResourceNotFoundException;
import org.wso2.carbon.apimgt.api.APIProvider;
import org.wso2.carbon.apimgt.api.FaultGatewaysException;
import org.wso2.carbon.apimgt.api.model.API;
import org.wso2.carbon.apimgt.api.model.APIIdentifier;
import org.wso2.carbon.apimgt.api.model.APIProduct;
import org.wso2.carbon.apimgt.api.model.APIProductIdentifier;
import org.wso2.carbon.apimgt.api.model.APIProductResource;
import org.wso2.carbon.apimgt.api.model.APIStatus;
import org.wso2.carbon.apimgt.api.model.ApiTypeWrapper;
import org.wso2.carbon.apimgt.api.model.Scope;
import org.wso2.carbon.apimgt.api.model.Tier;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.definitions.OASParserUtil;
import org.wso2.carbon.apimgt.impl.importexport.APIImportExportConstants;
import org.wso2.carbon.apimgt.impl.importexport.APIImportExportException;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * This is the util class which consists of all the functions for importing API Product.
 */
public class APIProductImportUtil {

    private static final Log log = LogFactory.getLog(APIProductImportUtil.class);

    private APIProductImportUtil() {
    }

    /**
     * This method imports dependent APIs of the API Product.
     *
     * @param path                     Location of the extracted folder of the API Product
     * @param currentUser              The current logged in user
     * @param isDefaultProviderAllowed Decision to keep or replace the provider
     * @param apiProvider              API Provider
     * @param overwriteAPIs            Whether to overwrite the APIs or not
     * @throws APIImportExportException if there is an error in importing an API
     */
    private static void importDependentAPIs(String path, String currentUser, boolean isDefaultProviderAllowed,
                                            APIProvider apiProvider, Boolean overwriteAPIs)
            throws APIImportExportException, IOException, APIManagementException {
        String apisDirectoryPath = path + File.separator + APIImportExportConstants.APIS_DIRECTORY;
        File apisDirectory = new File(apisDirectoryPath);
        File[] apisDirectoryListing = apisDirectory.listFiles();
        if (apisDirectoryListing != null) {
            for (File api : apisDirectoryListing) {
                String apiDirectoryPath = path + File.separator + APIImportExportConstants.APIS_DIRECTORY + File.separator + api.getName();
                // Get API Definition as JSON
                String jsonContent = APIAndAPIProductCommonUtil.getAPIDefinitionAsJson(apiDirectoryPath);
                if (jsonContent == null) {
                    throw new IOException("Cannot find API definition. api.json or api.yaml should present");
                }
                JsonElement configElement = new JsonParser().parse(jsonContent);
                JsonObject configObject = configElement.getAsJsonObject();

                //locate the "providerName" within the "id" and set it as the current user
                JsonObject apiProductId = configObject.getAsJsonObject(APIImportExportConstants.ID_ELEMENT);

                String provider = apiProductId.get(APIImportExportConstants.PROVIDER_ELEMENT).getAsString();
                String apiName = apiProductId.get(APIImportExportConstants.API_NAME_ELEMENT).getAsString();
                String apiVersion = apiProductId.get(APIImportExportConstants.VERSION_ELEMENT).getAsString();

                APIIdentifier apiIdentifier = new APIIdentifier(APIUtil.replaceEmailDomain(provider), apiName,
                        apiVersion);
                // Checking whether the API exists
                if (!apiProvider.isAPIAvailable(apiIdentifier)) {
                    // If the API is not already imported, import it
                    APIImportUtil.importAPI(apiDirectoryPath, currentUser, isDefaultProviderAllowed, apiProvider, false);
                } else {
                    // If the API is already imported, update if specified the overWriteAPIs flag,
                    // otherwise do not import/update the API. (Just skip it)
                    if (overwriteAPIs == true) {
                        APIImportUtil.importAPI(apiDirectoryPath, currentUser, isDefaultProviderAllowed, apiProvider, true);
                    }
                }
            }
        } else {
            String errMsg = "Error occurred while importing the API Product. No dependent APIs supplied";
            log.error(errMsg);
            throw new APIImportExportException(errMsg);
        }
    }

    /**
     * This method imports an API Product.
     *
     * @param pathToArchive            location of the extracted folder of the API Product
     * @param currentUser              the current logged in user
     * @param isDefaultProviderAllowed decision to keep or replace the provider
     * @throws APIImportExportException if there is an error in importing an API Product
     */
    public static void importAPIProduct(String pathToArchive, String currentUser, boolean isDefaultProviderAllowed,
                                 APIProvider apiProvider, Boolean overwriteAPIProduct, Boolean overwriteAPIs)
            throws APIImportExportException {

        String jsonContent = null;
        APIProduct importedApiProduct = null;
        APIProduct targetApiProduct; //target API Product when overwriteAPIProduct is true
        ApiTypeWrapper apiTypeWrapper;
        String prevProvider;
        String apiProductName;
        String apiProductVersion;
        String currentTenantDomain;
        String currentStatus;
        String targetStatus;
        String lifecycleAction = null;
        String pathToYamlFile = pathToArchive + APIImportExportConstants.YAML_API_FILE_LOCATION;
        String pathToJsonFile = pathToArchive + APIImportExportConstants.JSON_API_FILE_LOCATION;

        try {
            // import dependent APIs first
            importDependentAPIs(pathToArchive, currentUser, isDefaultProviderAllowed, apiProvider, overwriteAPIs);

            // Get API Definition as JSON
            jsonContent = APIAndAPIProductCommonUtil.getAPIDefinitionAsJson(pathToArchive);
            if (jsonContent == null) {
                throw new IOException("Cannot find API Product definition. api.json or api.yaml should present");
            }
            JsonElement configElement = new JsonParser().parse(jsonContent);
            JsonObject configObject = configElement.getAsJsonObject();

            //locate the "providerName" within the "id" and set it as the current user
            JsonObject apiProductId = configObject.getAsJsonObject(APIImportExportConstants.ID_ELEMENT);

            prevProvider = apiProductId.get(APIImportExportConstants.PROVIDER_ELEMENT).getAsString();
            apiProductName = apiProductId.get(APIImportExportConstants.API_PRODUCT_NAME_ELEMENT).getAsString();
            apiProductVersion = apiProductId.get(APIImportExportConstants.VERSION_ELEMENT).getAsString();
            // Remove spaces of API Product Name/version if present
            if (apiProductName != null && apiProductVersion != null) {
                apiProductId.addProperty(APIImportExportConstants.API_PRODUCT_NAME_ELEMENT,
                        apiProductName = apiProductName.replace(" ", ""));
                apiProductId.addProperty(APIImportExportConstants.VERSION_ELEMENT,
                        apiProductVersion = apiProductVersion.replace(" ", ""));
            } else {
                throw new IOException("API Product Name (id.apiProductName) and Version (id.version) must be provided in api.yaml");
            }

            String prevTenantDomain = MultitenantUtils
                    .getTenantDomain(APIUtil.replaceEmailDomainBack(prevProvider));
            currentTenantDomain = MultitenantUtils
                    .getTenantDomain(APIUtil.replaceEmailDomainBack(currentUser));

            // If the original provider is preserved,
            if (isDefaultProviderAllowed) {
                if (!StringUtils.equals(prevTenantDomain, currentTenantDomain)) {
                    String errorMessage = "Tenant mismatch! Please enable preserveProvider property "
                            + "for cross tenant API Product Import.";
                    throw new APIMgtAuthorizationFailedException(errorMessage);
                }
                importedApiProduct = new Gson().fromJson(configElement, APIProduct.class);
            } else {
                String currentUserWithDomain = APIUtil.replaceEmailDomain(currentUser);
                apiProductId.addProperty(APIImportExportConstants.PROVIDER_ELEMENT, currentUserWithDomain);

                importedApiProduct = new Gson().fromJson(configElement, APIProduct.class);
                //Replace context to match with current provider
                apiTypeWrapper = new ApiTypeWrapper(importedApiProduct);
                APIAndAPIProductCommonUtil.setCurrentProviderToAPIProperties(apiTypeWrapper, currentTenantDomain, prevTenantDomain);
            }

            // Store imported API Product status
            targetStatus = importedApiProduct.getState();
            if (Boolean.TRUE.equals(overwriteAPIProduct)) {
                String provider = APIUtil
                        .getAPIProviderFromAPINameVersionTenant(apiProductName, apiProductVersion, currentTenantDomain);
                APIProductIdentifier apiProductIdentifier = new APIProductIdentifier(APIUtil.replaceEmailDomain(provider), apiProductName,
                        apiProductVersion);
                // Checking whether the API Product exists
                if (!apiProvider.isAPIProductAvailable(apiProductIdentifier)) {
                    String errorMessage = "Error occurred while updating. API Product: " + apiProductName + StringUtils.SPACE
                            + APIConstants.API_DATA_VERSION + ": " + apiProductVersion + " not found";
                    throw new APIMgtResourceNotFoundException(errorMessage);
                }
                targetApiProduct = apiProvider.getAPIProduct(apiProductIdentifier);
                // Store target API Product status
                currentStatus = targetApiProduct.getState();
            } else {
                if (apiProvider.isAPIProductAvailable(importedApiProduct.getId())
                        || apiProvider.isApiNameWithDifferentCaseExist(apiProductName)) {
                    String errorMessage = "Error occurred while adding the API Product. A duplicate API Product already exists " +
                            "for " + importedApiProduct.getId().getName() + '-' + importedApiProduct.getId().getVersion();
                    throw new APIMgtResourceAlreadyExistsException(errorMessage);
                }

                if (apiProvider.isContextExist(importedApiProduct.getContext())) {
                    String errMsg = "Error occurred while adding the API Product [" + importedApiProduct.getId().getName()
                            + '-' + importedApiProduct.getId().getVersion() + "]. A duplicate context["
                            + importedApiProduct.getContext() + "] already exists";
                    throw new APIMgtResourceAlreadyExistsException(errMsg);
                }

                // Initialize to PUBLISHED when import
                currentStatus = APIStatus.PUBLISHED.toString();
            }
            //set the status of imported API to PUBLISHED (importing API Product) or current status of target API Product when updating
            importedApiProduct.setState(currentStatus);

            // check whether targetStatus is reachable from current status, if not throw an exception
            if (!currentStatus.equals(targetStatus)) {
                lifecycleAction = APIAndAPIProductCommonUtil.getLifeCycleAction(currentTenantDomain, currentStatus, targetStatus, apiProvider);
                if (lifecycleAction == null) {
                    String errMsg = "Error occurred while importing the API Product. " + targetStatus + " is not reachable from "
                            + currentStatus;
                    log.error(errMsg);
                    throw new APIImportExportException(errMsg);
                }
            }

            Set<Tier> allowedTiers;
            Set<Tier> unsupportedTiersList;
            allowedTiers = apiProvider.getTiers();

            if (!(allowedTiers.isEmpty())) {
                unsupportedTiersList = Sets.difference(importedApiProduct.getAvailableTiers(), allowedTiers);

                //If at least one unsupported tier is found, it should be removed before adding API Product
                if (!(unsupportedTiersList.isEmpty())) {
                    //Process is continued with a warning and only supported tiers are added to the importer API Product
                    unsupportedTiersList.forEach(unsupportedTier ->
                            log.warn("Tier name : " + unsupportedTier.getName() + " is not supported."));
                    //Remove the unsupported tiers before adding the API
                    importedApiProduct.removeAvailableTiers(unsupportedTiersList);
                }
            }
            if (Boolean.FALSE.equals(overwriteAPIProduct)) {
                //Add API Product in PUBLISHED state
                Map<API, List<APIProductResource>> apiToProductResourceMapping = apiProvider.addAPIProductWithoutPublishingToGateway(importedApiProduct);
                apiProvider.addAPIProductSwagger(apiToProductResourceMapping, importedApiProduct);
                APIProductIdentifier createdAPIProductIdentifier = importedApiProduct.getId();
                APIProduct createdProduct = apiProvider.getAPIProduct(createdAPIProductIdentifier);
                apiProvider.saveToGateway(createdProduct);
            }

            String swaggerContent = APIAndAPIProductCommonUtil.loadSwaggerFile(pathToArchive);

            //Load required properties from swagger to the API Product
            APIDefinition apiDefinition = OASParserUtil.getOASParser(swaggerContent);
            Set<Scope> scopes = apiDefinition.getScopes(swaggerContent);
            importedApiProduct.setScopes(scopes);


            // This is required to make scopes get effected
            Map<API, List<APIProductResource>> apiToProductResourceMapping = apiProvider.updateAPIProduct(importedApiProduct);
            apiProvider.updateAPIProductSwagger(apiToProductResourceMapping, importedApiProduct);

            //Since Image, documents, sequences and WSDL are optional, exceptions are logged and ignored in implementation
            ApiTypeWrapper apiTypeWrapperWithUpdatedApiProduct = new ApiTypeWrapper(importedApiProduct);
            APIAndAPIProductCommonUtil.addAPIOrAPIProductImage(pathToArchive, apiTypeWrapperWithUpdatedApiProduct, apiProvider);
            APIAndAPIProductCommonUtil.addAPIOrAPIProductDocuments(pathToArchive, apiTypeWrapperWithUpdatedApiProduct, apiProvider);

            if (apiProvider.isClientCertificateBasedAuthenticationConfigured()) {
                if (log.isDebugEnabled()) {
                    log.debug("Mutual SSL enabled. Importing client certificates.");
                }
                APIAndAPIProductCommonUtil.addClientCertificates(pathToArchive, apiProvider);
            }
        } catch (IOException e) {
            //Error is logged and APIImportExportException is thrown because adding API and swagger are mandatory steps
            String errorMessage = "Error while reading API Product meta information from path: " + pathToArchive;
            log.error(errorMessage, e);
            throw new APIImportExportException(errorMessage, e);
        } catch (FaultGatewaysException e) {
            String errorMessage = "Error while updating API Product: " + importedApiProduct.getId().getName();
            log.error(errorMessage, e);
            throw new APIImportExportException(errorMessage, e);
        } catch (APIManagementException e) {
            String errorMessage = "Error while importing API Product: ";
            if (importedApiProduct != null) {
                errorMessage += importedApiProduct.getId().getName() + StringUtils.SPACE + APIConstants.API_DATA_VERSION
                        + ": " + importedApiProduct.getId().getVersion();
            }
            log.error(errorMessage, e);
            throw new APIImportExportException(errorMessage, e);
        }
    }
}
