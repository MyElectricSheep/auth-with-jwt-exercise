CREATE TABLE IF NOT EXISTS users (
   id serial PRIMARY KEY,
   name VARCHAR (150) UNIQUE NOT NULL,
   password VARCHAR (150) NOT NULL,
   admin BOOLEAN NOT NULL DEFAULT TRUE,
   created_on TIMESTAMP NOT NULL
);