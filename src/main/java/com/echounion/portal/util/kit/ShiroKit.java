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
package com.echounion.portal.util.kit;

import org.apache.shiro.crypto.hash.Md5Hash;
import org.jasig.cas.authentication.handler.PasswordEncoder;
/**
 * Created by phuang on 2016/2/10.
 *
 *@author Misagh Moayyed
 * @author Charles Hasegawa (mailto:chasegawa@unicon.net)
 * @since 4.1.0
 */
public class ShiroKit implements PasswordEncoder {
    /**
     * 设置盐.
     */
    private  String salt;

    /**
     * 获取盐.
     * @return salt
     */
    public final  String getSalt() {
        return salt;
    }

    /**
     * 设置盐.
     * @param salt 盐
     */
    public final  void setSalt(final String salt) {
        this.salt = salt;
    }

    /**
     * 加密.
     * @param password 密码
     * @return 加密后的值
     */
    public static String md5(final String password) {
        return md5(password, null);
    }

    /**
     * 加密.
     * @param password 密码
     * @param salt  盐值
     * @return  加密后的值
     */
    public static String md5(final String password, final String salt) {
        String p;
        p = new Md5Hash(password, salt, 2).toHex();
        return p;
    }

    /**
     * 判断是否为空.
     * @param obj 值
     * @return 是否为空
     */
    public static boolean isEmpty(final Object obj) {

        if (obj instanceof String) {
            return "".equals(obj);
        }

        if (obj instanceof Integer) {
            return (Integer) obj == 0;
        }
        return obj == null;
    }

    @Override
    public String encode(final String password) {
        if (password == null) {
            return null;
        } else {
            try {
                return md5(password, salt);
            } catch (final Exception e) {
                throw new RuntimeException(e);
            }
        }
    }


}
