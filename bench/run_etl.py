import json, sys, time, tempfile, os, hashlib
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "bench"))
from gen import make_corpus
from aishield.detector import Detector
from aishield.normalize import normalize
from aishield.etl import spark_session, run_etl

docs = make_corpus(200, seed=2026)
det = Detector(); findings = []
for i, d in enumerate(docs):
    txt = normalize(d.text)
    for e in det.detect(txt):
        findings.append({"job_id": f"job{i}", "doc_id": f"doc{i:03d}", "entity_type": e.type, "start": e.start, "end": e.end,
                         "confidence": float(e.confidence), "value_hash": hashlib.sha256(e.value.encode()).hexdigest()[:16],
                         "text_len": len(txt)})
dup = findings[:25]  # inject duplicate detections to exercise the de-duplication step
findings_in = findings + [dict(f, confidence=f["confidence"] - 0.1) for f in dup]
t0 = time.perf_counter(); spark = spark_session(); t_start = time.perf_counter() - t0
out = tempfile.mkdtemp() + "/curated"
t0 = time.perf_counter(); per_doc = run_etl(spark, findings_in, out); n_docs = per_doc.count(); t_etl = time.perf_counter() - t0
try:
    back = spark.read.parquet(out)
    sample = back.orderBy("doc_id").select("doc_id", "entity_count", "distinct_types", "person_count", "email_count", "student_id_count", "density_per_1k").limit(5).toPandas()
except Exception:
    import pandas as pd
    pfiles = [os.path.join(dp, f) for dp, _, fs in os.walk(out) for f in fs if f.endswith(".parquet")]
    pdf = pd.read_parquet(pfiles[0])
    sample = pdf.sort_values("doc_id")[["doc_id", "entity_count", "distinct_types", "person_count", "email_count", "student_id_count", "density_per_1k"]].head(5)
size = sum(os.path.getsize(os.path.join(dp, f)) for dp, _, fs in os.walk(out) for f in fs)
R = dict(rows_in=len(findings_in), rows_dedup=len(findings), docs=n_docs, spark_start_s=round(t_start, 2), etl_s=round(t_etl, 2),
         parquet_files=sum(len(fs) for _, _, fs in os.walk(out)), parquet_kb=round(size / 1024, 1), sample=sample.to_dict("records"),
         spark_version=spark.version)
json.dump(R, open(os.path.join(ROOT, "bench", "etl.json"), "w"), indent=1, default=str)
print(json.dumps(R, indent=1, default=str)); spark.stop()
