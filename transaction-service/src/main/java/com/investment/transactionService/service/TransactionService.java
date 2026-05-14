package com.investment.transactionService.service;

import com.investment.transactionService.client.PortfolioClient;
import com.investment.transactionService.domain.Transaction;
import com.investment.transactionService.domain.TransactionType;
import com.investment.transactionService.dto.CreateTransactionRequest;
import com.investment.transactionService.dto.TransactionResponse;
import com.investment.transactionService.repository.TransactionRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class TransactionService {

    private final TransactionRepository transactionRepository;
    private final PortfolioClient portfolioClient;

    @Transactional
    public TransactionResponse register(String userId, CreateTransactionRequest request) {

        if (request.getType() == TransactionType.SELL) {
            validateSellQuantity(request.getPortfolioId(), request.getTicker(), request.getQuantity());
        }

        Transaction transaction = Transaction.builder()
                .userId(userId)
                .portfolioId(request.getPortfolioId())
                .ticker(request.getTicker().toUpperCase())
                .type(request.getType())
                .quantity(request.getQuantity())
                .price(request.getPrice())
                .total(request.getPrice().multiply(request.getQuantity()))
                .build();

        transaction = transactionRepository.save(transaction);

        syncPortfolio(request);

        log.info("Transaction registered: {} {} {} @ {} for user {}",
                request.getType(), request.getQuantity(),
                request.getTicker(), request.getPrice(), userId);

        return toResponse(transaction);
    }

    public List<TransactionResponse> findByPortfolio(String portfolioId, String ticker) {
        if (ticker != null && !ticker.isBlank()) {
            return transactionRepository
                    .findByPortfolioIdAndTickerOrderByExecutedAtDesc(portfolioId, ticker.toUpperCase())
                    .stream().map(this::toResponse).collect(Collectors.toList());
        }
        return transactionRepository
                .findByPortfolioIdOrderByExecutedAtDesc(portfolioId)
                .stream().map(this::toResponse).collect(Collectors.toList());
    }

    public List<TransactionResponse> findByUser(String userId) {
        return transactionRepository.findByUserIdOrderByExecutedAtDesc(userId)
                .stream().map(this::toResponse).collect(Collectors.toList());
    }

    // -------------------------------------------------------------------------

    private void validateSellQuantity(String portfolioId, String ticker, BigDecimal sellQty) {
        List<Transaction> history = transactionRepository
                .findByPortfolioIdAndTicker(portfolioId, ticker.toUpperCase());

        BigDecimal net = history.stream()
                .map(t -> t.getType() == TransactionType.BUY
                        ? t.getQuantity()
                        : t.getQuantity().negate())
                .reduce(BigDecimal.ZERO, BigDecimal::add);

        if (net.compareTo(sellQty) < 0) {
            throw new RuntimeException(
                    "Quantidade insuficiente para venda. Saldo disponível: " + net.toPlainString());
        }
    }

    private void syncPortfolio(CreateTransactionRequest request) {
        try {
            List<Transaction> history = transactionRepository
                    .findByPortfolioIdAndTicker(request.getPortfolioId(),
                            request.getTicker().toUpperCase());

            BigDecimal net = history.stream()
                    .map(t -> t.getType() == TransactionType.BUY
                            ? t.getQuantity()
                            : t.getQuantity().negate())
                    .reduce(BigDecimal.ZERO, BigDecimal::add);

            if (net.compareTo(BigDecimal.ZERO) <= 0) {
                portfolioClient.deletePosition(
                        request.getPortfolioId(),
                        request.getTicker().toUpperCase());
            } else {
                portfolioClient.addOrUpdatePosition(
                        request.getPortfolioId(),
                        request.getTicker().toUpperCase(),
                        request.getQuantity(),
                        request.getPrice());
            }
        } catch (Exception e) {
            log.warn("Falha ao sincronizar portfolio-service para {}: {}",
                    request.getTicker(), e.getMessage());
        }
    }

    public TransactionResponse toResponse(Transaction t) {
        return TransactionResponse.builder()
                .id(t.getId())
                .portfolioId(t.getPortfolioId())
                .userId(t.getUserId())
                .ticker(t.getTicker())
                .type(t.getType())
                .quantity(t.getQuantity())
                .price(t.getPrice())
                .total(t.getTotal())
                .executedAt(t.getExecutedAt())
                .build();
    }
}