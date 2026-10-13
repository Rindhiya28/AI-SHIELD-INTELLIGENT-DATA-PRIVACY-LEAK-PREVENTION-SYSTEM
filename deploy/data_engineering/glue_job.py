"""AWS Glue PySpark ETL Job script for AI Shield.
Reads raw JSON findings from S3, de-duplicates overlapping detections, aggregates privacy metrics per document,
and writes partitioned Parquet into the AWS Glue Data Catalog / S3 analytics lakehouse.
"""
import sys
from awsglue.transforms import *
from awsglue.utils import getResolvedOptions
from pyspark.context import SparkContext
from awsglue.context import GlueContext
from awsglue.job import Job
from pyspark.sql import Window
from pyspark.sql import functions as F

# Retrieve Job Arguments
args = getResolvedOptions(sys.argv, ['JOB_NAME', 'INPUT_S3_PATH', 'OUTPUT_S3_PATH'])

sc = SparkContext()
glueContext = GlueContext(sc)
spark = glueContext.spark_session
job = Job(glueContext)
job.init(args['JOB_NAME'], args)

input_path = args['INPUT_S3_PATH']
output_path = args['OUTPUT_S3_PATH']

# 1. Read JSON findings from S3
findings_df = spark.read.json(input_path)

# 2. De-duplicate overlapping spans keeping the highest confidence entity
window_spec = Window.partitionBy("doc_id", "start", "end").orderBy(F.col("confidence").desc())
dedup_df = findings_df.withColumn("rk", F.row_number().over(window_spec)).filter("rk = 1").drop("rk")

# 3. Document-level analytics aggregation with entity type breakdown
entity_types = ["PERSON", "EMAIL", "PHONE", "STUDENT_ID", "ID_NUMBER", "ADDRESS", "DATE_OF_BIRTH"]
agg_df = (dedup_df.groupBy("doc_id", "job_id")
          .agg(
              F.count("*").alias("entity_count"),
              F.max("text_len").alias("text_len"),
              F.countDistinct("entity_type").alias("distinct_types"),
              F.round(F.avg("confidence"), 3).alias("mean_confidence"),
              *[F.sum((F.col("entity_type") == t).cast("int")).alias(f"{t.lower()}_count") for t in entity_types]
          )
          .withColumn("density_per_1k", F.round(F.col("entity_count") * 1000 / F.col("text_len"), 2))
          .withColumn("processed_date", F.current_date()))

# 4. Write partitioned Parquet to S3 Curated zone
(agg_df.write
 .partitionBy("processed_date")
 .mode("append")
 .parquet(output_path))

job.commit()
