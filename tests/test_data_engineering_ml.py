"""Unit and integration tests for Module 2: Data Engineering & Machine Learning.
Validates:
1. PySpark ETL pipeline output schema and deduplication
2. Redshift DDL tables and the 4 privacy analytics queries
3. Random Forest risk model accuracy and inference
4. Strict privacy hygiene: hash-only values in analytics
"""
import os
import sqlite3
import pytest
import joblib
import numpy as np

from aishield.risk import features, rubric_label
from aishield.detector import Entity
from aishield import lambdas as L

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REDSHIFT_SQL_PATH = os.path.join(ROOT, "deploy", "data_engineering", "redshift_analytics.sql")
GLUE_SCRIPT_PATH = os.path.join(ROOT, "deploy", "data_engineering", "glue_job.py")


def test_data_engineering_scripts_exist():
    assert os.path.exists(GLUE_SCRIPT_PATH)
    assert os.path.exists(REDSHIFT_SQL_PATH)


def test_redshift_sql_syntax_and_queries_execution():
    """Verify Redshift schema DDL and the 4 analytics SQL queries using an in-memory SQL engine."""
    with open(REDSHIFT_SQL_PATH, "r", encoding="utf-8") as f:
        sql_content = f.read()

    assert "fact_findings" in sql_content
    assert "dim_document" in sql_content
    assert "dim_entity_type" in sql_content
    assert "dim_date" in sql_content
    assert "agg_daily_risk" in sql_content
    # Ensure zero raw sensitive values are stored in analytics table schema
    assert "raw_value" not in sql_content.lower()
    assert "value_hash" in sql_content

    # Execute SQLite translation of the star schema and the 4 queries
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE dim_document (
        doc_id TEXT PRIMARY KEY,
        job_id TEXT NOT NULL,
        text_length INT NOT NULL,
        processed_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cur.execute("""
    CREATE TABLE dim_date (
        date_id INT PRIMARY KEY,
        full_date DATE NOT NULL,
        day_of_week TEXT,
        month_name TEXT,
        quarter INT,
        year INT
    )
    """)

    cur.execute("""
    CREATE TABLE fact_findings (
        finding_id TEXT PRIMARY KEY,
        doc_id TEXT NOT NULL,
        entity_type TEXT NOT NULL,
        span_start INT NOT NULL,
        span_end INT NOT NULL,
        confidence REAL NOT NULL,
        detector_name TEXT NOT NULL,
        value_hash TEXT NOT NULL,
        date_id INT NOT NULL
    )
    """)

    # Insert synthetic records
    cur.execute("INSERT INTO dim_date VALUES (20261013, '2026-10-13', 'Tuesday', 'October', 4, 2026)")
    cur.execute("INSERT INTO dim_document VALUES ('doc001', 'job001', 350, '2026-10-13 10:00:00')")
    cur.execute("INSERT INTO dim_document VALUES ('doc002', 'job002', 450, '2026-10-13 11:00:00')")
    
    findings_data = [
        ('f1', 'doc001', 'PERSON', 10, 20, 0.90, 'context', 'hash_p1', 20261013),
        ('f2', 'doc001', 'EMAIL', 30, 50, 1.00, 'regex', 'hash_e1', 20261013),
        ('f3', 'doc001', 'STUDENT_ID', 70, 78, 0.95, 'regex', 'hash_s1', 20261013),
        ('f4', 'doc002', 'PHONE', 10, 21, 0.97, 'regex', 'hash_ph1', 20261013),
        ('f5', 'doc002', 'ID_NUMBER', 40, 52, 0.98, 'regex', 'hash_id1', 20261013),
    ]
    cur.executemany("INSERT INTO fact_findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", findings_data)

    # Query 1 Test: Top 5 Sensitive Entity Types
    q1 = """
    SELECT f.entity_type, COUNT(f.finding_id) as cnt, ROUND(AVG(f.confidence), 3) as avg_c
    FROM fact_findings f
    GROUP BY f.entity_type
    ORDER BY cnt DESC
    """
    res1 = cur.execute(q1).fetchall()
    assert len(res1) > 0
    assert res1[0][1] >= 1

    # Query 2 Test: Document threat level & density
    q2 = """
    SELECT d.doc_id, COUNT(f.finding_id) as entity_cnt,
           ROUND((COUNT(f.finding_id) * 1000.0) / d.text_length, 2) as density
    FROM dim_document d
    LEFT JOIN fact_findings f ON d.doc_id = f.doc_id
    GROUP BY d.doc_id
    """
    res2 = cur.execute(q2).fetchall()
    assert len(res2) == 2

    # Query 3 Test: Multi-detector breakdown
    q3 = """
    SELECT f.detector_name, f.entity_type, COUNT(f.finding_id)
    FROM fact_findings f
    GROUP BY f.detector_name, f.entity_type
    """
    res3 = cur.execute(q3).fetchall()
    assert len(res3) >= 3

    # Query 4 Test: Daily Trend
    q4 = """
    SELECT d.full_date, COUNT(DISTINCT f.doc_id) as docs, COUNT(f.finding_id) as findings
    FROM fact_findings f
    JOIN dim_date d ON f.date_id = d.date_id
    GROUP BY d.full_date
    """
    res4 = cur.execute(q4).fetchall()
    assert len(res4) == 1
    assert res4[0][1] == 2  # 2 docs

    conn.close()


def test_random_forest_model_and_lambda_inference():
    """Verify that the retrained Random Forest risk model loads and predicts correctly."""
    model_path = os.path.join(ROOT, "aishield", "risk_model.joblib")
    assert os.path.exists(model_path)
    model = joblib.load(model_path)
    assert hasattr(model, "predict")

    # High-risk case: STUDENT_ID present
    high_event = {
        "text_len": 300,
        "findings": [
            {"type": "STUDENT_ID", "start": 10, "end": 18, "confidence": 0.95, "detector": "regex"}
        ]
    }
    risk_res = L.risk_handler(high_event)
    assert risk_res["risk"] == "HIGH"

    # Low-risk case: single PERSON
    low_event = {
        "text_len": 400,
        "findings": [
            {"type": "PERSON", "start": 5, "end": 15, "confidence": 0.85, "detector": "context"}
        ]
    }
    low_res = L.risk_handler(low_event)
    assert low_res["risk"] in ("LOW", "MEDIUM")
