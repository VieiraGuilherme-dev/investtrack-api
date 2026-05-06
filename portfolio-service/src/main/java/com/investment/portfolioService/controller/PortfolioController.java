package com.investment.portfolioService.controller;

import com.investment.portfolioService.dto.CreatePortfolioRequest;
import com.investment.portfolioService.dto.PortfolioResponse;
import com.investment.portfolioService.service.PortfolioService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/portfolios")
@RequiredArgsConstructor
public class PortfolioController {

    private final PortfolioService portfolioService;

    @PostMapping
    public ResponseEntity<PortfolioResponse> create(
            @Valid @RequestBody CreatePortfolioRequest request,
            Authentication auth) {
        return ResponseEntity.status(201)
                .body(portfolioService.create(auth.getName(), request));
    }

    @GetMapping
    public ResponseEntity<List<PortfolioResponse>> findAll(Authentication auth) {
        return ResponseEntity.ok(portfolioService.findAllByUser(auth.getName()));
    }

    @GetMapping("/{id}")
    public ResponseEntity<PortfolioResponse> findById(
            @PathVariable String id,
            Authentication auth) {
        return ResponseEntity.ok(portfolioService.findByIdAndUser(id, auth.getName()));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(
            @PathVariable String id,
            Authentication auth) {
        portfolioService.delete(id, auth.getName());
        return ResponseEntity.noContent().build();
    }
}