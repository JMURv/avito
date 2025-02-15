package db

const getUser = `
SELECT id, username, password, balance 
FROM users
WHERE username = $1
`

const getUserBalance = `
SELECT u.balance FROM users u WHERE u.id=$1
`

const getUserInventory = `
SELECT inv.quantity, i.name
FROM inventory inv
JOIN items i ON i.id=inv.item_id
WHERE inv.user_id=$1
LIMIT $2 OFFSET $3
`

const getUserTransactions = `
SELECT 
    t.from_user_id,
    u.username AS from_username,
    t.to_user_id,
    u1.username AS to_username,
    t.amount 
FROM transactions t
JOIN users u ON u.id=t.from_user_id
JOIN users u1 ON u1.id=t.to_user_id
WHERE from_user_id=$1 OR to_user_id=$1
LIMIT $2 OFFSET $3
`

const createUser = `
INSERT INTO users (username, password, balance) 
VALUES ($1, $2, $3) 
RETURNING id
`

const getItem = `
SELECT id, name, price 
FROM items 
WHERE name=$1
`

const sendCoinFrom = `
UPDATE users SET balance = balance - $1
WHERE id = $2
`

const sendCoinTo = `
UPDATE users SET balance = balance + $1
WHERE username=$2
`

const createTransaction = `
INSERT INTO transactions (from_user_id, to_user_id, amount)
VALUES ($1, (SELECT id FROM users WHERE username=$2), $3)
`

const upsertInventory = `
INSERT INTO inventory (user_id, item_id, quantity)
VALUES ($1, $2, 1)
ON CONFLICT (user_id, item_id)
DO UPDATE SET quantity = inventory.quantity + 1;
`
