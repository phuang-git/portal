/*
 * Licensed to Apereo under one or more contributor license
 * agreements. See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * Apereo licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License.  You may obtain a
 * copy of the License at the following location:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package com.echounion.portal.util;

import com.echounion.portal.util.kit.ShiroKit;
import org.jasig.cas.adaptors.jdbc.AbstractJdbcUsernamePasswordAuthenticationHandler;
import org.jasig.cas.authentication.HandlerResult;
import org.jasig.cas.authentication.PreventedException;
import org.jasig.cas.authentication.UsernamePasswordCredential;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.IncorrectResultSizeDataAccessException;

import javax.security.auth.login.AccountNotFoundException;
import javax.security.auth.login.FailedLoginException;
import javax.validation.constraints.NotNull;
import java.security.GeneralSecurityException;
import java.util.List;

/**
 * Created by phuang on 2016/2/10.
 * @author Misagh Moayyed
 * @author Charles Hasegawa (mailto:chasegawa@unicon.net)
 * @since 4.1.0
 */
public class MyQueryDatabaseAuthenticationHandler extends AbstractJdbcUsernamePasswordAuthenticationHandler {
    /**
     * The Sql statement to execute.
     */
    @NotNull
    private String sql;

    @Override
    protected HandlerResult authenticateUsernamePasswordInternal(final UsernamePasswordCredential credential)
            throws GeneralSecurityException, PreventedException {
        final String username = credential.getUsername();
        final ShiroKit shiroKit = (ShiroKit) this.getPasswordEncoder();
        shiroKit.setSalt(username);
        final String encryptedPassword = shiroKit.encode(credential.getPassword());

        try {
            final String e = (String) this.getJdbcTemplate().queryForObject(this.sql, String.class, new Object[]{username});
            if (!e.equals(encryptedPassword)) {
                throw new FailedLoginException("Password does not match value on record.");
            }
        } catch (final IncorrectResultSizeDataAccessException var5) {
            if (var5.getActualSize() == 0) {
                throw new AccountNotFoundException(username + " not found with SQL query");
            }

            throw new FailedLoginException("Multiple records found for " + username);
        } catch (final DataAccessException var6) {
            throw new PreventedException("SQL exception while executing query for " + username, var6);
        }

        return this.createHandlerResult(credential, this.principalFactory.createPrincipal(username), (List) null);
    }

    public void setSql(final String sql) {
        this.sql = sql;
    }
}
