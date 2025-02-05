package com.maxiflexy.security.demo;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/demo")
@RequiredArgsConstructor
public class DemoController {

    @GetMapping
    public ResponseEntity<String> test(){
        var user = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        var userEmail = ((UserDetails) user).getUsername();
        return ResponseEntity.ok("Hello from secured endpoint" + userEmail);
    }
}
