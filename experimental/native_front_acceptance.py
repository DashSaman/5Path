"""A small-file check is a regression gate, not a throughput benchmark."""
import math

def nonregressing(before_seconds, candidate_seconds):
 values=(before_seconds,candidate_seconds)
 if any(type(x)not in (int,float) or not math.isfinite(x) or x<=0 for x in values):return False
 return candidate_seconds<=max(before_seconds*1.35,before_seconds+.15)
