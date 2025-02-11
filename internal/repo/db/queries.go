package db

const userGet = `
SELECT id, username, password, balance 
FROM users
WHERE username = $1
`

const userCreate = `
INSERT INTO users (username, password, balance) 
VALUES ($1, $2, $3) 
RETURNING id
`

const getInfo = `
SELECT u.balance
FROM users u
JOIN inventory AS i ON i.user_id=u.id
JOIN transactions AS t ON t.from_user_id=u.id
JOIN transactions AS t1 ON t1.to_user_id=u.id
`
