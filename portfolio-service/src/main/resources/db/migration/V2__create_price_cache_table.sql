CREATE TABLE price_cache (
    id            VARCHAR(36)    PRIMARY KEY,
    ticker        VARCHAR(10)    NOT NULL UNIQUE,
    current_price NUMERIC(15, 8) NOT NULL,
    updated_at    TIMESTAMP      NOT NULL
);

CREATE INDEX idx_price_cache_ticker ON price_cache(ticker);
