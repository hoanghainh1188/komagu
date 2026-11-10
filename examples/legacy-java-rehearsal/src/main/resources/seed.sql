CREATE TABLE users (id BIGINT PRIMARY KEY, username VARCHAR(40) UNIQUE, password VARCHAR(80), display_name VARCHAR(80), role VARCHAR(20));
CREATE TABLE orders (id BIGINT PRIMARY KEY, owner_id BIGINT, item VARCHAR(80), note VARCHAR(200), total INT);
CREATE TABLE invoices (id BIGINT PRIMARY KEY, owner_id BIGINT, amount INT);
INSERT INTO users VALUES (1, 'rehearsal-a', 'rehearsal-only-a', 'Rehearsal Owner', 'user');
INSERT INTO users VALUES (2, 'rehearsal-b', 'rehearsal-only-b', 'Rehearsal Attacker', 'user');
INSERT INTO orders VALUES (101, 1, 'owner-widget', 'original note', 1200);
INSERT INTO orders VALUES (201, 2, 'attacker-widget', 'attacker note', 300);
INSERT INTO invoices VALUES (101, 1, 1200);
INSERT INTO invoices VALUES (201, 2, 300);
