package com.erick.security.domain;

import lombok.Data;

/**
 * @author You
 * @Date 2024/7/27 18:03
 */
@Data
public class User {
    /**
     * 用户名
     */
    private String username;
    /**
     * 密码
     */
    private String password;
    /**
     * 邮箱
     */
    private String email;
    /**
     * 名称
     */
    private String name;
}
