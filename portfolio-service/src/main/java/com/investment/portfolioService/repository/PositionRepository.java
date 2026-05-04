package com.investment.portfolioService.repository;

import com.investment.portfolioService.domain.Position;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface PositionRepository extends JpaRepository<Position, String> {

    List<Position> findByPortfolioId(String portfolioId);

    Optional<Position> findByPortfolioIdAndTicker(String portfolioId, String ticker);

    boolean existsByPortfolioIdAndTicker(String portfolioId, String ticker);
}