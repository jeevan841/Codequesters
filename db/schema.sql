CREATE TABLE leads (
    id SERIAL PRIMARY KEY,
    phone TEXT,
    business_type TEXT,
    team_size TEXT,
    revenue_estimate TEXT,
    meeting_time TEXT,
    call_summary TEXT,
    transcript TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email TEXT UNIQUE,
    password TEXT
);
