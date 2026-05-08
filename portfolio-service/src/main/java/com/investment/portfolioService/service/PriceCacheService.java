package com.investment.portfolioService.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.investment.portfolioService.domain.PriceCache;
import com.investment.portfolioService.repository.PriceCacheRepository;
import com.investment.portfolioService.repository.PositionRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class PriceCacheService {

    private static final String YAHOO_URL =
            "https://query1.finance.yahoo.com/v8/finance/chart/{ticker}?interval=1d&range=1d";

    private final PriceCacheRepository priceCacheRepository;
    private final PositionRepository positionRepository;
    private final WebClient webClient;

    @Scheduled(fixedRate = 300_000)
    public void refreshPrices() {
        List<String> tickers = positionRepository.findDistinctTickers();
        for (String ticker : tickers) {
            try {
                BigDecimal price = fetchPrice(ticker);
                PriceCache cache = priceCacheRepository.findByTicker(ticker)
                        .orElse(PriceCache.builder().ticker(ticker).build());
                cache.setCurrentPrice(price);
                cache.setUpdatedAt(LocalDateTime.now());
                priceCacheRepository.save(cache);
                log.debug("Price updated for {}: {}", ticker, price);
            } catch (Exception e) {
                log.warn("Failed to fetch price for ticker {}: {}", ticker, e.getMessage());
            }
        }
    }

    public BigDecimal getPriceOrFallback(String ticker, BigDecimal fallback) {
        return priceCacheRepository.findByTicker(ticker)
                .map(PriceCache::getCurrentPrice)
                .orElse(fallback);
    }

    private BigDecimal fetchPrice(String ticker) {
        JsonNode body = webClient.get()
                .uri(YAHOO_URL, ticker)
                .retrieve()
                .bodyToMono(JsonNode.class)
                .block();

        String price = body.path("chart")
                .path("result")
                .get(0)
                .path("meta")
                .path("regularMarketPrice")
                .asText();

        return new BigDecimal(price);
    }
}