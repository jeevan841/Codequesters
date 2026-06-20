CREATE TABLE leads (
    id SERIAL PRIMARY KEY,
    phone TEXT,
    business_type TEXT,
    team_size TEXT,
    revenue_estimate TEXT,
    meeting_time TEXT,
    call_summary TEXT,
    transcript TEXT,
    lead_score INT DEFAULT 0,
    lead_quality TEXT DEFAULT 'Cold',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email TEXT UNIQUE,
    password TEXT
);
