package com.investment.transactionService.controller;

import com.investment.transactionService.dto.CreateTransactionRequest;
import com.investment.transactionService.dto.TickerSummaryResponse;
import com.investment.transactionService.dto.TransactionResponse;
import com.investment.transactionService.service.TransactionService;
import com.investment.transactionService.service.TransactionSummaryService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/transactions")
@RequiredArgsConstructor
public class TransactionController {

    private final TransactionService transactionService;
    private final TransactionSummaryService transactionSummaryService;

    @PostMapping
    public ResponseEntity<TransactionResponse> register(
            @Valid @RequestBody CreateTransactionRequest request,
            Authentication auth) {
        return ResponseEntity.status(201)
                .body(transactionService.register(auth.getName(), request));
    }

    @GetMapping
    public ResponseEntity<List<TransactionResponse>> findByPortfolio(
            @RequestParam String portfolioId,
            @RequestParam(required = false) String ticker) {
        return ResponseEntity.ok(transactionService.findByPortfolio(portfolioId, ticker));
    }

    @GetMapping("/me")
    public ResponseEntity<List<TransactionResponse>> findMine(Authentication auth) {
        return ResponseEntity.ok(transactionService.findByUser(auth.getName()));
    }

    @GetMapping("/summary")
    public ResponseEntity<List<TickerSummaryResponse>> summary(
            @RequestParam String portfolioId) {
        return ResponseEntity.ok(transactionSummaryService.summarizeByPortfolio(portfolioId));
    }
}