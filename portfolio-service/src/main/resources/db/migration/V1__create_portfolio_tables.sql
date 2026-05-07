CREATE TABLE portfolios (
    id         VARCHAR(36)  PRIMARY KEY,
    user_id    VARCHAR(36)  NOT NULL,
    name       VARCHAR(100) NOT NULL,
    created_at TIMESTAMP    NOT NULL
);

CREATE TABLE positions (
    id            VARCHAR(36)    PRIMARY KEY,
    portfolio_id  VARCHAR(36)    NOT NULL REFERENCES portfolios(id),
    ticker        VARCHAR(10)    NOT NULL,
    quantity      NUMERIC(15, 8) NOT NULL,
    average_price NUMERIC(15, 8) NOT NULL,
    updated_at    TIMESTAMP      NOT NULL
);

CREATE INDEX idx_portfolios_user_id ON portfolios(user_id);
CREATE INDEX idx_positions_portfolio_id ON positions(portfolio_id);
CREATE UNIQUE INDEX idx_positions_portfolio_ticker ON positions(portfolio_id, ticker);