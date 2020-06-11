/*
*  Copyright (c) 2005-2011, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.apimgt.impl.dao;


import com.google.gson.Gson;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.wso2.carbon.apimgt.api.*;
import org.wso2.carbon.apimgt.api.dto.ConditionDTO;
import org.wso2.carbon.apimgt.api.dto.ConditionGroupDTO;
import org.wso2.carbon.apimgt.api.dto.KeyManagerConfigurationDTO;
import org.wso2.carbon.apimgt.api.dto.UserApplicationAPIUsage;
import org.wso2.carbon.apimgt.api.model.*;
import org.wso2.carbon.apimgt.api.model.botDataAPI.BotDetectionData;
import org.wso2.carbon.apimgt.api.model.policy.*;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.APIManagerConfiguration;
import org.wso2.carbon.apimgt.impl.ThrottlePolicyConstants;
import org.wso2.carbon.apimgt.impl.dao.constants.SQLConstants;
import org.wso2.carbon.apimgt.impl.dao.constants.SQLConstants.ThrottleSQLConstants;
import org.wso2.carbon.apimgt.impl.dto.*;
import org.wso2.carbon.apimgt.impl.factory.KeyManagerHolder;
import org.wso2.carbon.apimgt.impl.factory.SQLConstantManagerFactory;
import org.wso2.carbon.apimgt.impl.internal.ServiceReferenceHolder;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;
import org.wso2.carbon.apimgt.impl.utils.ApplicationUtils;
import org.wso2.carbon.apimgt.impl.utils.RemoteUserManagerClient;
import org.wso2.carbon.apimgt.impl.utils.SharedDBUtil;
import org.wso2.carbon.apimgt.impl.workflow.WorkflowConstants;
import org.wso2.carbon.apimgt.impl.workflow.WorkflowExecutorFactory;
import org.wso2.carbon.apimgt.impl.workflow.WorkflowStatus;
import org.wso2.carbon.core.util.CryptoException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.DBUtils;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigDecimal;
import java.nio.charset.Charset;
import java.sql.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * This class represent the ApiMgtDAO.
 */
public class SharedDAO {
    private static final Log log = LogFactory.getLog(SharedDAO.class);
    private static SharedDAO INSTANCE = null;

    private boolean forceCaseInsensitiveComparisons = false;
    private boolean multiGroupAppSharingEnabled = false;
    private static boolean initialAutoCommit = false;

    private final Object scopeMutex = new Object();

    private SharedDAO() {
        APIManagerConfiguration configuration = ServiceReferenceHolder.getInstance()
                .getAPIManagerConfigurationService().getAPIManagerConfiguration();

        String caseSensitiveComparison = ServiceReferenceHolder.getInstance().
                getAPIManagerConfigurationService().getAPIManagerConfiguration().getFirstProperty(APIConstants.API_STORE_FORCE_CI_COMPARISIONS);
        if (caseSensitiveComparison != null) {
            forceCaseInsensitiveComparisons = Boolean.parseBoolean(caseSensitiveComparison);
        }

        multiGroupAppSharingEnabled = APIUtil.isMultiGroupAppSharingEnabled();
    }

    public List<String> getRoleNamesMatchingPermission(String permission) throws APIManagementException {
        Connection conn = null;
        PreparedStatement ps = null;
        List<String> versionList = new ArrayList<String>();
        ResultSet resultSet = null;

        String sqlQuery = SQLConstants.GET_ROLES_WITH_SPECIFIED_PERMISSION;
        try {
            conn = SharedDBUtil.getConnection();
            ps = conn.prepareStatement(sqlQuery);
            ps.setString(1, permission);
            resultSet = ps.executeQuery();
            while (resultSet.next()) {
                versionList.add(resultSet.getString("UM_ROLE_NAME"));
            }
        } catch (SQLException e) {
            handleException("Failed to get Roles matching the permission" + permission, e);
        } finally {
            SharedDBUtil.closeAllConnections(ps, conn, resultSet);
        }
        return versionList;
    }

    private void handleException(String msg, Throwable t) throws APIManagementException {
        log.error(msg, t);
        throw new APIManagementException(msg, t);
    }

    /**
     * Method to get the instance of the ApiMgtDAO.
     *
     * @return {@link SharedDAO} instance
     */
    public static SharedDAO getInstance() {
        if (INSTANCE == null) {
            INSTANCE = new SharedDAO();
        }

        return INSTANCE;
    }
}
