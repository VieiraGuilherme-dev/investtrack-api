package com.investment.transactionService.dto;


import com.investment.transactionService.domain.TransactionType;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.math.BigDecimal;

@Data
public class CreateTransactionRequest {

    @NotBlank
    private String portfolioId;

    @NotBlank
    private String ticker;

    @NotNull
    private TransactionType type;

    @NotNull
    @DecimalMin(value = "0.00000001")
    private BigDecimal quantity;

    @NotNull
    @DecimalMin(value = "0.00000001")
    private BigDecimal price;


}
