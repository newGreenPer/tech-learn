package com.erick.security.rest;

import com.erick.security.domain.dto.UserDto;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

/**
 * @author You
 * @Date 2024/7/27 18:09
 */
@RequestMapping("/authorize")
@RestController
@Validated
public class AuthorizeResource {

    @PostMapping("/register")
    public UserDto register(@RequestBody @Valid UserDto userDto) {
        return userDto;
    }
}
