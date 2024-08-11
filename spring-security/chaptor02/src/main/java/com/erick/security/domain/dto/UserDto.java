package com.erick.security.domain.dto;

import com.erick.security.validation.annotation.PasswordMatches;
import com.erick.security.validation.annotation.ValidEmail;
import com.erick.security.validation.annotation.ValidPassword;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.io.Serializable;

/**
 * @author You
 * @Date 2024/7/27 18:04
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@PasswordMatches
@Validated
public class UserDto implements Serializable {
    /**
     * 用户名
     */
    @NotNull
    @NotBlank(message = "用户名不能为空")
    @Size(min = 4, max = 50, message = "用户名长度必须在4到50个字符之间")
    private String username;
    /**
     * 密码
     */
    @NotNull
    @NotBlank
    @Size(min = 8, max = 20, message = "密码必须在8到20个字符之间")
    @ValidPassword
    private String password;
    @NotNull
    @NotBlank
    @Size(min = 8, max = 20, message = "密码必须在8到20个字符之间")
    private String matchingPassword;
    /**
     * 邮箱
     */
    @NotNull
    @ValidEmail
    private String email;
    /**
     * 名称
     */
    @NotNull
    @NotBlank
    @Size(min = 4, max = 50, message = "姓名长度必须在4到50个字符之间")
    private String name;
}
