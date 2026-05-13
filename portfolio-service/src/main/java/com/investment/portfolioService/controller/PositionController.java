package com.investment.portfolioService.controller;

import com.investment.portfolioService.dto.PositionResponse;
import com.investment.portfolioService.service.PositionService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;
import java.util.List;

@RestController
@RequestMapping("/portfolios/{portfolioId}/positions")
@RequiredArgsConstructor
public class PositionController {

    private final PositionService positionService;

    @PostMapping
    public ResponseEntity<PositionResponse> addOrUpdate(
            @PathVariable String portfolioId,
            @RequestParam String ticker,
            @RequestParam BigDecimal quantity,
            @RequestParam BigDecimal price,
            Authentication auth) {
        return ResponseEntity.status(201)
                .body(positionService.addOrUpdate(
                        portfolioId, auth.getName(), ticker, quantity, price));
    }

    @GetMapping
    public ResponseEntity<List<PositionResponse>> findAll(
            @PathVariable String portfolioId,
            Authentication auth) {
        return ResponseEntity.ok(positionService.findByPortfolio(portfolioId));
    }

    @PatchMapping("/{ticker}/reduce")
    public ResponseEntity<PositionResponse> reduce(
            @PathVariable String portfolioId,
            @PathVariable String ticker,
            @RequestParam BigDecimal quantity,
            Authentication auth) {
        return ResponseEntity.ok(
                positionService.reduceQuantity(portfolioId, ticker, quantity)
        );
    }

    @DeleteMapping("/{ticker}")
    public ResponseEntity<Void> delete(
            @PathVariable String portfolioId,
            @PathVariable String ticker,
            Authentication auth) {
        positionService.delete(portfolioId, ticker, auth.getName());
        return ResponseEntity.noContent().build();
    }
}