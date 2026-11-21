## The cost of a wrong decision

A false alert, a post-cutoff assertion released as other and a human referral entail different costs. Define loss as four counts multiplied by their weights and added. FP is a determinate control flagged as positive. FN is a positive closed as other. R counts all referrals, whatever the eventual decision. U is an indeterminate reference automatically closed in either direction. A referred positive therefore reduces automatic sensitivity, but incurs a single referral charge in this model. No assumption of perfect human correction or measured downstream cost is made.

| Illustrative profile | False alert (FP) | Positive released (FN) | Referral (R) | Ambiguity closed (U) | Assumed capacity |
|---|---:|---:|---:|---:|---|
| Administrative review | 12 | 25 | 1 | 14 | No preset referral cap |
| Customer support | 4 | 5 | 2 | 3 | At most 20% referred |

The weights are hypothetical units for sensitivity analysis. Both types of correct decisions cost zero. These are neither economic estimates nor regulatory thresholds. The profiles were designed after observing the main outcome. Within each profile the selection algorithm sees only the 48 calibration cases, compares thresholds 2–8 and considers review-all. A higher threshold demands more evidence before closing a proposition automatically. Ties favour the higher numerical threshold.

Both profiles selected 5 on calibration with 6/48 referrals and no errors among decisions. On the new challenge that threshold yielded one false alert, zero positives closed as other, 24 referrals and three indeterminate cases closed automatically. The administrative loss is **78 units**, compared with **48** for reviewing all 48 cases. Customer support incurs **61 units** and refers 50%, exceeding the assumed 20% cap. None of the tested numerical thresholds met that capacity constraint on the new set. The full threshold table is in [scenarios.json](costs/scenarios.json).

Actual use depends on local review costs, prevalence and consequences for the affected person. These results support deferring autonomous disposition in administrative disputes. Measured reviewer time and a representative sample would allow an operator to replace the illustrative weights and repeat the selection.
