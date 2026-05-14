package com.investment.transactionService.service;


import com.investment.transactionService.domain.Transaction;
import com.investment.transactionService.domain.TransactionType;
import com.investment.transactionService.dto.TickerSummaryResponse;
import com.investment.transactionService.repository.TransactionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class TransactionSummaryService {

    private final TransactionRepository transactionRepository;

    public List<TickerSummaryResponse> summarizeByPortfolio(String portfolioId){
        List<Transaction> all = transactionRepository
                .findByPortfolioIdOrderByExecutedAtDesc(portfolioId);

        return all.stream()
                .map(Transaction::getTicker)
                .distinct()
                .map(ticker -> buildSummary(portfolioId, ticker, all))
                .collect(Collectors.toList());
    }

    private TickerSummaryResponse buildSummary(String portfolioId, String ticker, List<Transaction> all) {

        List<Transaction> tickerTxs = all.stream()
                .filter(t -> t.getTicker().equals(ticker))
                .collect(Collectors.toList());


        BigDecimal bought = tickerTxs.stream()
                .filter(t -> t.getType() == TransactionType.BUY)
                .map(Transaction::getQuantity)
                .reduce(BigDecimal.ZERO, BigDecimal::add);


        BigDecimal sold = tickerTxs.stream()
                .filter(t -> t.getType() == TransactionType.SELL)
                .map(Transaction::getQuantity)
                .reduce(BigDecimal.ZERO, BigDecimal::add);


        BigDecimal totalInvested = tickerTxs.stream()
                .filter(t -> t.getType() == TransactionType.BUY)
                .map(Transaction::getTotal)
                .reduce(BigDecimal.ZERO, BigDecimal::add);


        BigDecimal totalRealized = tickerTxs.stream()
                .filter(t -> t.getType() == TransactionType.SELL)
                .map(Transaction::getTotal)
                .reduce(BigDecimal.ZERO, BigDecimal::add);


        return TickerSummaryResponse.builder()
                .portfolioId(portfolioId)
                .ticker(ticker)
                .totalBoughtQuantity(bought)
                .totalSoldQuantity(sold)
                .netQuantity(bought.subtract(sold))
                .totalInvested(totalRealized)
                .totalRealized(totalRealized)
                .transactionCount(tickerTxs.size())
                .build();

    }
}
