"""Data engineering (Glue-style PySpark job): de-duplicate findings, aggregate per document, write Parquet."""
from __future__ import annotations

from typing import Any, Dict, List

from pyspark.sql import SparkSession, Window
from pyspark.sql import functions as F


def spark_session(name: str = "AIShieldETL") -> SparkSession:
    import os, sys
    os.environ["PYSPARK_PYTHON"] = sys.executable
    os.environ["PYSPARK_DRIVER_PYTHON"] = sys.executable
    return (SparkSession.builder.appName(name).master("local[2]")
            .config("spark.ui.enabled", "false").config("spark.driver.bindAddress", "127.0.0.1")
            .config("spark.driver.host", "127.0.0.1").config("spark.sql.shuffle.partitions", "2").getOrCreate())


def run_etl(spark: SparkSession, findings: List[Dict[str, Any]], out_dir: str):
    """findings: one record per detection with job_id, doc_id, entity_type, start, end, confidence, value_hash, text_len."""
    df = spark.createDataFrame(findings)
    w = Window.partitionBy("doc_id", "start", "end").orderBy(F.col("confidence").desc())
    dedup = df.withColumn("rk", F.row_number().over(w)).filter("rk = 1").drop("rk")
    per_doc = (dedup.groupBy("doc_id")
               .agg(F.count("*").alias("entity_count"),
                    F.max("text_len").alias("text_len"),
                    F.countDistinct("entity_type").alias("distinct_types"),
                    F.round(F.avg("confidence"), 3).alias("mean_confidence"),
                    *[F.sum((F.col("entity_type") == t).cast("int")).alias(f"{t.lower()}_count")
                      for t in ["PERSON", "EMAIL", "PHONE", "STUDENT_ID", "ID_NUMBER", "ADDRESS", "DATE_OF_BIRTH"]])
               .withColumn("density_per_1k", F.round(F.col("entity_count") * 1000 / F.col("text_len"), 2)))
    try:
        per_doc.write.mode("overwrite").parquet(out_dir)
    except Exception as e:
        # On Windows local Spark without winutils.exe, write parquet directly via PyArrow/Pandas
        import os
        os.makedirs(out_dir, exist_ok=True)
        pdf = per_doc.toPandas()
        pdf.to_parquet(os.path.join(out_dir, "part-00000.parquet"), index=False)
    return per_doc
