package com.investment.portfolioService.repository;

import com.investment.portfolioService.domain.PriceCache;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface PriceCacheRepository extends JpaRepository<PriceCache, String> {

    Optional<PriceCache> findByTicker(String ticker);
}
