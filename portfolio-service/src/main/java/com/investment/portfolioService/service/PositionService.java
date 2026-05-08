package com.investment.portfolioService.service;

import com.investment.portfolioService.domain.Portfolio;
import com.investment.portfolioService.domain.Position;
import com.investment.portfolioService.dto.PositionResponse;
import com.investment.portfolioService.repository.PortfolioRepository;
import com.investment.portfolioService.repository.PositionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class PositionService {

    private final PositionRepository positionRepository;
    private final PortfolioRepository portfolioRepository;
    private final PriceCacheService priceCacheService;

    public PositionResponse addOrUpdate(String portfolioId, String userId,
                                        String ticker, BigDecimal quantity,
                                        BigDecimal price) {

        Portfolio portfolio = portfolioRepository.findByIdAndUserId(portfolioId, userId)
                .orElseThrow(() -> new RuntimeException("Carteira não encontrada"));

        Position position = positionRepository
                .findByPortfolioIdAndTicker(portfolioId, ticker)
                .map(existing -> updateAveragePrice(existing, quantity, price))
                .orElseGet(() -> Position.builder()
                        .portfolio(portfolio)
                        .ticker(ticker)
                        .quantity(quantity)
                        .averagePrice(price)
                        .build());

        position = positionRepository.save(position);
        return toResponse(position, priceCacheService.getPriceOrFallback(ticker, price));
    }

    public List<PositionResponse> findByPortfolio(String portfolioId) {
        return positionRepository.findByPortfolioId(portfolioId)
                .stream()
                .map(p -> toResponse(p, priceCacheService.getPriceOrFallback(p.getTicker(), p.getAveragePrice())))
                .collect(Collectors.toList());
    }

    public void delete(String portfolioId, String ticker, String userId) {
        portfolioRepository.findByIdAndUserId(portfolioId, userId)
                .orElseThrow(() -> new RuntimeException("Carteira não encontrada"));

        Position position = positionRepository
                .findByPortfolioIdAndTicker(portfolioId, ticker)
                .orElseThrow(() -> new RuntimeException("Posição não encontrada"));

        positionRepository.delete(position);
    }

    private Position updateAveragePrice(Position existing,
                                        BigDecimal newQty,
                                        BigDecimal newPrice) {
        BigDecimal totalCost = existing.getAveragePrice()
                .multiply(existing.getQuantity())
                .add(newPrice.multiply(newQty));

        BigDecimal totalQty = existing.getQuantity().add(newQty);

        BigDecimal newAverage = totalCost.divide(totalQty, 8, RoundingMode.HALF_UP);

        existing.setQuantity(totalQty);
        existing.setAveragePrice(newAverage);
        return existing;
    }

    private PositionResponse toResponse(Position position, BigDecimal currentPrice) {
        BigDecimal totalInvested = position.getAveragePrice()
                .multiply(position.getQuantity());

        BigDecimal currentValue = currentPrice
                .multiply(position.getQuantity());

        BigDecimal profitLoss = currentValue.subtract(totalInvested);

        BigDecimal profitLossPercent = totalInvested.compareTo(BigDecimal.ZERO) == 0
                ? BigDecimal.ZERO
                : profitLoss.divide(totalInvested, 4, RoundingMode.HALF_UP)
                .multiply(BigDecimal.valueOf(100));

        return PositionResponse.builder()
                .id(position.getId())
                .ticker(position.getTicker())
                .quantity(position.getQuantity())
                .averagePrice(position.getAveragePrice())
                .currentPrice(currentPrice)
                .totalInvested(totalInvested)
                .currentValue(currentValue)
                .profitLoss(profitLoss)
                .profitLossPercent(profitLossPercent)
                .updatedAt(position.getUpdatedAt())
                .build();
    }
}