#!/bin/bash
echo "CREATE DATABASE oauthdb" | psql
echo "CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\"" | psql -d oauthdb
cat schema.sql | psql -d oauthdb
echo "GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO oauthdb" | psql -d oauthdb
echo "insert into oauth_clients VALUES('123', 'pass123', 'https://example.com/callback');" | psql -d oauthdb
