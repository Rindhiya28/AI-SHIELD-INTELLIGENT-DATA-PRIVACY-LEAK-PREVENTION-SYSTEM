"""Console demo: scan, review, redact and validate one document, then verify the audit ledger."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from aishield.governor import Governor
from aishield.ledger import sha256_hex

DOC = ("My name is Rindhiya A. My email is rindhiya@example.com, and my register number is 23UAI091. "
       "Reach me on 98765 43210 or 9 8 7 6 5 4 3 2 1 0. Date of birth: 14/03/2004. "
       "Please summarize my project report.")
g = Governor()
r = g.process(DOC, "INC-0001")
print("INPUT    :", DOC)
print("DECISION :", r.decision.value, "| risk:", r.risk_rule, "| redaction rounds:", r.rounds, "| residual:", r.residual)
print("FINDINGS :")
for i, e in enumerate(r.entities):
    print(f"  #{i} {e.type:<14} span=[{e.start:>3},{e.end:>3}) conf={e.confidence:.2f} detector={e.detector:<9} hash={sha256_hex(e.value)[:12]}")
print("OUTPUT   :", r.sanitized)
print("LEDGER   :")
for b in g.ledger.chain:
    print(f"  #{b.index} {b.stage:<8} {b.status:<9} prev={b.prev_hash[:10]} hash={b.hash[:10]}")
print("INTEGRITY:", "VALID" if g.ledger.verify() else "BROKEN")
g.ledger.chain[1].status = "TAMPERED"
print("AFTER EDITING BLOCK #1 ->", "VALID" if g.ledger.verify() else "BROKEN (tampering detected)")
