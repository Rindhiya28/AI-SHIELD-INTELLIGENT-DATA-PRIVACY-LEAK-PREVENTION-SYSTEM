-- =========================================================================
-- AI Shield: Redshift Serverless Data Warehouse DDL & Analytics Suite
-- Star Schema Model: Fact findings, Dimension tables, and Aggregated Daily Risk
-- Privacy Rule: Only SHA-256 hashes of sensitive values stored in analytics.
-- =========================================================================

-- 1. Dimension Tables
CREATE TABLE IF NOT EXISTS dim_document (
    doc_id VARCHAR(64) PRIMARY KEY,
    job_id VARCHAR(64) NOT NULL,
    text_length INT NOT NULL,
    processed_timestamp TIMESTAMP DEFAULT SYSDATE
);

CREATE TABLE IF NOT EXISTS dim_entity_type (
    entity_type_id INT IDENTITY(1,1) PRIMARY KEY,
    entity_type VARCHAR(32) NOT NULL UNIQUE,
    risk_tier VARCHAR(16) NOT NULL, -- LOW, MEDIUM, HIGH
    requires_approval BOOLEAN DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS dim_date (
    date_id INT PRIMARY KEY, -- Format: YYYYMMDD
    full_date DATE NOT NULL UNIQUE,
    day_of_week VARCHAR(10) NOT NULL,
    month_name VARCHAR(10) NOT NULL,
    quarter INT NOT NULL,
    year INT NOT NULL
);

-- 2. Fact Table: fact_findings (Individual detections with SHA-256 hashes only)
CREATE TABLE IF NOT EXISTS fact_findings (
    finding_id VARCHAR(64) PRIMARY KEY,
    doc_id VARCHAR(64) NOT NULL REFERENCES dim_document(doc_id),
    entity_type VARCHAR(32) NOT NULL,
    span_start INT NOT NULL,
    span_end INT NOT NULL,
    confidence FLOAT NOT NULL,
    detector_name VARCHAR(32) NOT NULL,
    value_hash VARCHAR(64) NOT NULL, -- SHA-256 Digest ONLY (Zero raw PII)
    date_id INT NOT NULL REFERENCES dim_date(date_id),
    created_at TIMESTAMP DEFAULT SYSDATE
);

-- 3. Aggregated Reporting Table: agg_daily_risk
CREATE TABLE IF NOT EXISTS agg_daily_risk (
    report_date DATE NOT NULL,
    risk_level VARCHAR(16) NOT NULL,
    total_documents INT NOT NULL,
    total_findings INT NOT NULL,
    avg_entity_density FLOAT NOT NULL,
    high_risk_entity_count INT NOT NULL,
    updated_at TIMESTAMP DEFAULT SYSDATE,
    PRIMARY KEY (report_date, risk_level)
);

-- =========================================================================
-- Redshift Serverless COPY Commands (Loads from S3 Parquet)
-- =========================================================================
-- COPY dim_document FROM 's3://aishield-curated-data/dim_document/'
-- IAM_ROLE 'arn:aws:iam::111122223333:role/AIShieldRedshiftRole'
-- FORMAT AS PARQUET;

-- COPY fact_findings FROM 's3://aishield-curated-data/fact_findings/'
-- IAM_ROLE 'arn:aws:iam::111122223333:role/AIShieldRedshiftRole'
-- FORMAT AS PARQUET;

-- =========================================================================
-- 4 Analytics Business Queries (Privacy Intelligence)
-- =========================================================================

-- Query 1: Top 5 Most Frequent Sensitive Entity Types & Detection Confidence
SELECT 
    f.entity_type,
    COUNT(f.finding_id) AS total_occurrences,
    ROUND(AVG(f.confidence), 3) AS avg_confidence,
    COUNT(DISTINCT f.doc_id) AS impacted_documents
FROM fact_findings f
GROUP BY f.entity_type
ORDER BY total_occurrences DESC
LIMIT 5;

-- Query 2: High-Risk Document Distribution by Entity Density (per 1,000 characters)
SELECT 
    d.doc_id,
    d.text_length,
    COUNT(f.finding_id) AS entity_count,
    ROUND((COUNT(f.finding_id) * 1000.0) / d.text_length, 2) AS density_per_1k,
    CASE 
        WHEN SUM(CASE WHEN f.entity_type IN ('STUDENT_ID', 'ID_NUMBER', 'ADDRESS') THEN 1 ELSE 0 END) > 0 THEN 'CRITICAL'
        WHEN COUNT(f.finding_id) > 5 THEN 'ELEVATED'
        ELSE 'STANDARD'
    END AS document_threat_level
FROM dim_document d
LEFT JOIN fact_findings f ON d.doc_id = f.doc_id
GROUP BY d.doc_id, d.text_length
ORDER BY density_per_1k DESC;

-- Query 3: Multi-Detector Accuracy & Attribution Benchmark
SELECT 
    f.detector_name,
    f.entity_type,
    COUNT(f.finding_id) AS detections_count,
    ROUND(AVG(f.confidence), 3) AS mean_detector_confidence
FROM fact_findings f
GROUP BY f.detector_name, f.entity_type
ORDER BY detections_count DESC;

-- Query 4: Daily Trend Analysis of High-Risk Privacy Exposures
SELECT 
    d.full_date,
    COUNT(DISTINCT f.doc_id) AS scanned_documents,
    COUNT(f.finding_id) AS total_pii_detected,
    SUM(CASE WHEN f.entity_type IN ('STUDENT_ID', 'ID_NUMBER', 'ADDRESS') THEN 1 ELSE 0 END) AS high_risk_spis
FROM fact_findings f
JOIN dim_date d ON f.date_id = d.date_id
GROUP BY d.full_date
ORDER BY d.full_date DESC;
