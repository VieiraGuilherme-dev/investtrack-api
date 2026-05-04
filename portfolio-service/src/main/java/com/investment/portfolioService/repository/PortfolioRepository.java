package com.investment.portfolioService.repository;

import com.investment.portfolioService.domain.Portfolio;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface PortfolioRepository extends JpaRepository<Portfolio, String> {

    List<Portfolio> findByUserId(String userId);

    Optional<Portfolio> findByIdAndUserId(String id, String userId);

    boolean existsByNameAndUserId(String name, String userId);
}