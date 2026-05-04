package com.investment.portfolioService.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class CreatePortfolioRequest {

    @NotBlank
    private String name;
}