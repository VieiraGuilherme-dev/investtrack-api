package com.investment.transactionService.config;

import feign.RequestInterceptor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

@Configuration
public class FeignConfig {

    @Bean
    public RequestInterceptor authForwardingInterceptor() {

        return template -> {

            ServletRequestAttributes attrs =
                    (ServletRequestAttributes)
                            RequestContextHolder.getRequestAttributes();

            if (attrs == null) {
                return;
            }

            String authHeader =
                    attrs.getRequest()
                            .getHeader("Authorization");

            if (authHeader != null && !authHeader.isBlank()) {
                template.header("Authorization", authHeader);
            }
        };
    }
}