package com.investment.transactionService.repository;

import com.investment.transactionService.domain.Transaction;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface TransactionRepository extends JpaRepository<Transaction, String> {

    List<Transaction> findByPortfolioIdOrderByExecutedAtDesc(String portfolioId);

    List<Transaction> findByPortfolioIdAndTickerOrderByExecutedAtDesc(
            String portfolioId,
            String ticker
    );

    List<Transaction> findByPortfolioIdAndTicker(
            String portfolioId,
            String ticker
    );

    List<Transaction> findByUserIdOrderByExecutedAtDesc(String userId);
}