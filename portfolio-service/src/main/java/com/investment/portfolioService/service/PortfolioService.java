package com.investment.portfolioService.service;

import com.investment.portfolioService.domain.Portfolio;
import com.investment.portfolioService.dto.CreatePortfolioRequest;
import com.investment.portfolioService.dto.PortfolioResponse;
import com.investment.portfolioService.dto.PositionResponse;
import com.investment.portfolioService.repository.PortfolioRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class PortfolioService {

    private final PortfolioRepository portfolioRepository;
    private final PositionService positionService;

    public PortfolioResponse create(String userId, CreatePortfolioRequest request) {
        if (portfolioRepository.existsByNameAndUserId(request.getName(), userId)) {
            throw new RuntimeException("Carteira com esse nome já existe");
        }

        Portfolio portfolio = Portfolio.builder()
                .userId(userId)
                .name(request.getName())
                .build();

        portfolio = portfolioRepository.save(portfolio);
        return toResponse(portfolio);
    }

    public List<PortfolioResponse> findAllByUser(String userId) {
        return portfolioRepository.findByUserId(userId)
                .stream()
                .map(this::toResponse)
                .collect(Collectors.toList());
    }

    public PortfolioResponse findByIdAndUser(String id, String userId) {
        Portfolio portfolio = portfolioRepository.findByIdAndUserId(id, userId)
                .orElseThrow(() -> new RuntimeException("Carteira não encontrada"));

        List<PositionResponse> positions = positionService.findByPortfolio(id);

        PortfolioResponse response = toResponse(portfolio);
        response.setPositions(positions);
        return response;
    }

    public void delete(String id, String userId) {
        Portfolio portfolio = portfolioRepository.findByIdAndUserId(id, userId)
                .orElseThrow(() -> new RuntimeException("Carteira não encontrada"));
        portfolioRepository.delete(portfolio);
    }

    private PortfolioResponse toResponse(Portfolio portfolio) {
        return PortfolioResponse.builder()
                .id(portfolio.getId())
                .name(portfolio.getName())
                .userId(portfolio.getUserId())
                .createdAt(portfolio.getCreatedAt())
                .build();
    }
}