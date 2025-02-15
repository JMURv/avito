CREATE TABLE IF NOT EXISTS users (
    id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255)        NOT NULL,
    balance  INT                 NOT NULL
        CONSTRAINT positive_balance CHECK (balance > 0)
);

CREATE TABLE IF NOT EXISTS items (
    id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name  VARCHAR(255),
    price INT NOT NULL
        CONSTRAINT positive_price CHECK (price > 0)
);

CREATE TABLE IF NOT EXISTS inventory (
    user_id  UUID NOT NULL,
    item_id  UUID NOT NULL,
    quantity INT  NOT NULL
        CONSTRAINT positive_quantity CHECK (quantity > 0),
    PRIMARY KEY (user_id, item_id),
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    FOREIGN KEY (item_id) REFERENCES items (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS transactions (
    id           SERIAL PRIMARY KEY,
    from_user_id UUID NOT NULL,
    to_user_id   UUID NOT NULL,
    amount       INT  NOT NULL CHECK (amount > 0),
    FOREIGN KEY (from_user_id) REFERENCES users (id) ON DELETE SET NULL,
    FOREIGN KEY (to_user_id) REFERENCES users (id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_user_username ON users (username);
CREATE INDEX IF NOT EXISTS idx_inventory_user ON inventory (user_id);
CREATE INDEX IF NOT EXISTS idx_inventory_item ON inventory (item_id);
CREATE INDEX IF NOT EXISTS idx_transactions_from ON transactions (from_user_id);
CREATE INDEX IF NOT EXISTS idx_transactions_to ON transactions (to_user_id);

INSERT INTO items (name, price)
VALUES ('t-shirt', 80),
       ('cup', 20),
       ('book', 50),
       ('pen', 10),
       ('powerbank', 200),
       ('hoody', 300),
       ('umbrella', 200),
       ('socks', 10),
       ('wallet', 50),
       ('pink-hoody', 500)
ON CONFLICT DO NOTHING;