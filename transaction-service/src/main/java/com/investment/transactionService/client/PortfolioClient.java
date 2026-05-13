package com.investment.transactionService.client;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;

@FeignClient(
        name = "portfolio-service",
        url = "${portfolio-service.url}"
)
public interface PortfolioClient {

    @PostMapping("/portfolios/{portfolioId}/positions")
    void addOrUpdatePosition(
            @PathVariable("portfolioId") String portfolioId,
            @RequestParam("ticker") String ticker,
            @RequestParam("quantity") BigDecimal quantity,
            @RequestParam("price") BigDecimal price
    );

    @DeleteMapping("/portfolios/{portfolioId}/positions/{ticker}")
    void deletePosition(
            @PathVariable("portfolioId") String portfolioId,
            @PathVariable("ticker") String ticker
    );
}