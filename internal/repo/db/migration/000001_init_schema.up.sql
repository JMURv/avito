CREATE TABLE users (
    id       UUID PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255)        NOT NULL,
    balance  INT                 NOT NULL
        CONSTRAINT positive_balance CHECK (balance > 0)
);

CREATE TABLE items (
    name  VARCHAR(255) PRIMARY KEY,
    price INT                 NOT NULL
        CONSTRAINT positive_price CHECK (price > 0)
);

CREATE TABLE inventory (
    user_id  UUID NOT NULL,
    item_name  VARCHAR(255) NOT NULL,
    quantity INT  NOT NULL
        CONSTRAINT positive_quantity CHECK (quantity > 0),
    PRIMARY KEY (user_id, item_name),
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    FOREIGN KEY (item_name) REFERENCES items (name) ON DELETE CASCADE
);

CREATE TABLE transactions (
    id           UUID PRIMARY KEY,
    from_user_id UUID NOT NULL,
    to_user_id   UUID NOT NULL,
    amount       INT  NOT NULL CHECK (amount > 0),
    FOREIGN KEY (from_user_id) REFERENCES users (id) ON DELETE SET NULL,
    FOREIGN KEY (to_user_id) REFERENCES users (id) ON DELETE SET NULL
);

CREATE INDEX idx_inventory_user ON inventory(user_id);
CREATE INDEX idx_transactions_from ON transactions(from_user_id);
CREATE INDEX idx_transactions_to ON transactions(to_user_id);
