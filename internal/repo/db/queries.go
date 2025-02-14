package db

const getUser = `
SELECT id, username, password, balance 
FROM users
WHERE username = $1
`

const getUserBalance = `
SELECT u.balance FROM users WHERE u.id=$1
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
    u.name AS from_username,
    t.to_user_id,
    u1.name AS to_username,
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
UPDATE users SET amount=amount-$1
WHERE id=$2
`

const sendCoinTo = `
UPDATE users SET amount=amount+$1
WHERE username=$2
`

const createTransaction = `
INSERT INTO transactions (from_user_id, to_user_id, amount)
VALUES ($1, $2, $3)
`

const createInventory = `
INSERT INTO inventory (user_id, item_id, quantity)
VALUES ($1, $2, $3)
`

const getInventoryQuantity = `
SELECT quantity FROM inventory
WHERE user_id=$1 AND item_id=$2
`
