package com.investment.transactionService.dto;


import com.investment.transactionService.domain.TransactionType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TransactionResponse {

    private String id;
    private String portfolioId;
    private String userId;
    private String ticker;
    private TransactionType type;
    private BigDecimal quantity;
    private BigDecimal price;
    private BigDecimal total;
    private LocalDateTime executedAt;

}
