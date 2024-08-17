package com.erick.security.rest;

import lombok.Data;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

/**
 * @author You
 * @Date 2024/7/13 18:37
 */
@RestController
@RequestMapping("/api")
public class UserResource {

    @GetMapping("/greeting")
    public String greeting() {
        return "Hello World";
    }

    @PostMapping("/greeting")
    public String makeGreeting(@RequestParam("name") String name,
                               @RequestBody Profile profile) {
        return "Hello make " + name + "\n "+ profile.gender +"\n"+profile.idNo;
    }

    @PutMapping("/greeting/{name}")
    public String putGreeting(@PathVariable("name") String name){
        return "Hello put "+name;
    }

    @GetMapping("/principal")
    public Authentication getPrincipal(){
        return SecurityContextHolder.getContext().getAuthentication();
    }

    @Data
    static class Profile{
        String idNo;
        String gender;
    }
}
