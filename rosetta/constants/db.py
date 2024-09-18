QUERY_TYPE = [ "SELECT", "INSERT", "UPDATE", "DELETE", "ALTER", "CREATE", "DROP", "TRUNCATE", "GRANT", "REVOKE", "MERGE", "CALL"]
DATABASE_NAME = [
    "users_db",
    "products_db",
    "orders_db",
    "inventory_db",
    "payments_db",
    "transactions_db",
    "accounting_db",
    "customers_db",
    "employees_db",
    "payroll_db",
    "recruitment_db",
    "attendance_db",
    "cms_db",
    "blog_db",
    "media_db",
    "articles_db"
]
QUERY = [
    # Normal SELECT Queries
    "SELECT * FROM users_db WHERE user_id = 123;",
    "SELECT * FROM payments_db WHERE user_id = 123 ORDER BY transaction_date DESC;",
    "SELECT name, price FROM products_db WHERE product_id = 567;",
    "SELECT * FROM employees_db WHERE department = 'HR';",
    "SELECT * FROM products_db WHERE category = 'Electronics';",
    "SELECT COUNT(*) FROM orders_db WHERE order_date BETWEEN '2024-09-01' AND '2024-09-30';",
    "SELECT product_id, SUM(quantity) FROM orders_db GROUP BY product_id;",
    "SELECT employee_name, salary FROM payroll_db WHERE salary > 5000;",
    "SELECT AVG(transaction_amount) FROM payments_db WHERE user_id = 123;",

    # Normal INSERT Queries
    "INSERT INTO users_db (user_id, name, email, signup_date) VALUES (124, 'John Doe', 'johndoe@example.com', '2024-09-12');",
    "INSERT INTO orders_db (order_id, user_id, product_id, quantity, order_date) VALUES (999, 123, 567, 2, '2024-09-12');",
    "INSERT INTO payments_db (transaction_id, user_id, amount, transaction_date) VALUES (555, 123, 120.50, '2024-09-12');",
    "INSERT INTO products_db (product_id, name, price, category) VALUES (1001, 'Laptop', 1500.00, 'Electronics');",
    "INSERT INTO employees_db (employee_id, name, department, hire_date) VALUES (200, 'Jane Doe', 'HR', '2024-09-10');",
    "INSERT INTO transactions_db (transaction_id, user_id, amount, transaction_date) VALUES (789, 234, 500.75, '2024-09-11');",
    "INSERT INTO cms_db (post_id, title, content, author) VALUES (12, 'New Blog Post', 'This is the content of the post', 'admin');",

    # Normal UPDATE Queries
    "UPDATE users_db SET email = 'newemail@example.com' WHERE user_id = 123;",
    "UPDATE inventory_db SET stock = 50 WHERE product_id = 567;",
    "UPDATE payments_db SET status = 'refunded' WHERE transaction_id = 555;",
    "UPDATE orders_db SET status = 'shipped' WHERE order_id = 999;",
    "UPDATE inventory_db SET stock = stock - 1 WHERE product_id = 1001;",
    "UPDATE customers_db SET address = '123 New Street' WHERE customer_id = 567;",

    # Normal DELETE Queries
    "DELETE FROM users_db WHERE user_id = 999;",
    "DELETE FROM products_db WHERE product_id = 1000;",
    "DELETE FROM attendance_db WHERE employee_id = 101 AND date = '2024-09-11';",
    "DELETE FROM blog_db WHERE post_id = 5;",
    "DELETE FROM transactions_db WHERE transaction_date < '2023-01-01';",
    "DELETE FROM employees_db WHERE hire_date < '2020-01-01';",

    # Normal ALTER Queries
    "ALTER TABLE users_db ADD COLUMN phone_number VARCHAR(20);",
    "ALTER TABLE products_db MODIFY COLUMN price DECIMAL(10, 2);",
    "ALTER TABLE payments_db ADD COLUMN transaction_status VARCHAR(20);",
    "ALTER TABLE employees_db RENAME COLUMN hire_date TO start_date;",

    # Normal CREATE Queries
    "CREATE TABLE user_addresses (address_id INT PRIMARY KEY, user_id INT, address_line VARCHAR(255), city VARCHAR(100), postal_code VARCHAR(20));",
    "CREATE INDEX idx_user_email ON users_db (email);",

    # Normal DROP Queries
    "DROP TABLE archived_orders;",
    "DROP INDEX idx_product_sku ON products_db;",

    # Malicious SQL Injection Queries
    "SELECT * FROM users_db WHERE user_id = '1' OR '1'='1';",
    "SELECT * FROM payments_db WHERE transaction_id = '1'; DROP TABLE payments_db;",
    "SELECT * FROM users_db WHERE username = 'admin' AND password = '' OR '1'='1';",
    "SELECT * FROM users_db WHERE password LIKE '%'; -- or '1'='1';",

    # Malicious Unauthorized Data Manipulation
    "UPDATE users_db SET password = 'hacked_password' WHERE username = 'admin';",
    "DELETE FROM payments_db WHERE '1'='1';",
    "INSERT INTO users_db (user_id, username, password, role) VALUES (999, 'attacker', 'password123', 'admin');",

    # Malicious Privilege Escalation Queries
    "GRANT ALL PRIVILEGES ON *.* TO 'attacker'@'%' IDENTIFIED BY 'password';",
    "CREATE USER 'hacker'@'localhost' IDENTIFIED BY 'password';",
    "GRANT ALL PRIVILEGES ON *.* TO 'hacker'@'localhost';",

    # Additional Malicious Queries
    "UPDATE employees_db SET salary = 10000 WHERE employee_id = 200 AND '1'='1';",
    "DROP TABLE users_db; -- Malicious query to drop a table",
    "SELECT * FROM users_db WHERE email = 'admin@example.com' AND '1'='1';"
]

