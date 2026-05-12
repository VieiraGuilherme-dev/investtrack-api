package com.investment.transactionService.dto;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TickerSummaryResponse {

    private String portfolioId;
    private String ticker;

    private BigDecimal totalBoughtQuantity;

    private BigDecimal totalSoldQuantity;

    private BigDecimal netQuantity;

    private BigDecimal totalInvested;

    private BigDecimal totalRealized;

    private long transactionCount;

}
