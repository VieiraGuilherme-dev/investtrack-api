package com.investment.portfolioService.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PortfolioResponse {

    private String id;
    private String name;
    private String userId;
    private LocalDateTime createdAt;
    private List<PositionResponse> positions;
}