# APIGuard Detection Accuracy Evaluation

_Generated 2026-10-30 17:27 UTC by `evaluation/run_evaluation.py`._

## Method
Each target was scanned with all four check categories. Results were collapsed to unique (check, endpoint) pairs and compared with `evaluation/ground_truth.yaml`, whose labels were derived from the targets' source code rather than from scanner output. A pair counts as *flagged* when APIGuard reports it CONFIRMED or SUSPECTED; SKIPPED results are excluded.

## Results by target
| Target | Pairs | TP | FP | TN | FN | Precision | Recall | F1 | Accuracy |
| :--- | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| APIGuard demo API - vulnerable | 36 | 27 | 0 | 9 | 0 | 100.0% | 100.0% | 100.0% | 100.0% |
| APIGuard demo API - secure | 35 | 0 | 0 | 35 | 0 | n/a | n/a | n/a | 100.0% |
| VAmPI - vulnerable | 27 | 5 | 0 | 22 | 0 | 100.0% | 100.0% | 100.0% | 100.0% |
| VAmPI - secure mode | 27 | 2 | 0 | 25 | 0 | 100.0% | 100.0% | 100.0% | 100.0% |

## Results by origin
| Benchmark | Pairs | TP | FP | TN | FN | Precision | Recall | F1 | Accuracy |
| :--- | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| APIGuard demo API (own) | 71 | 27 | 0 | 44 | 0 | 100.0% | 100.0% | 100.0% | 100.0% |
| VAmPI (third-party) | 54 | 7 | 0 | 47 | 0 | 100.0% | 100.0% | 100.0% | 100.0% |
| **All targets** | 125 | 34 | 0 | 91 | 0 | 100.0% | 100.0% | 100.0% | 100.0% |

## Results by category
| Category | Pairs | TP | FP | TN | FN | Precision | Recall | F1 | Accuracy |
| :--- | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| Authentication | 58 | 13 | 0 | 45 | 0 | 100.0% | 100.0% | 100.0% | 100.0% |
| Authorization | 16 | 7 | 0 | 9 | 0 | 100.0% | 100.0% | 100.0% | 100.0% |
| Input Validation | 26 | 5 | 0 | 21 | 0 | 100.0% | 100.0% | 100.0% | 100.0% |
| Data Exposure | 25 | 9 | 0 | 16 | 0 | 100.0% | 100.0% | 100.0% | 100.0% |

## Scan statistics
| Target | Checks run | PASS | CONFIRMED | SUSPECTED | Errors | Duration |
| :--- | --: | --: | --: | --: | --: | --: |
| APIGuard demo API - vulnerable | 45 | 9 | 36 | 0 | 0 | 1067 ms |
| APIGuard demo API - secure | 44 | 44 | 0 | 0 | 0 | 1080 ms |
| VAmPI - vulnerable | 34 | 28 | 5 | 0 | 0 | 1139 ms |
| VAmPI - secure mode | 34 | 31 | 2 | 0 | 0 | 1065 ms |

## Coverage of VAmPI's published vulnerabilities
APIGuard detected **3 of 4** published VAmPI vulnerabilities that fall inside its scope, and **3 of 9** overall.

| VAmPI vulnerability | In APIGuard scope | Detected | Notes |
| :--- | :-: | :-: | :--- |
| Broken Object Level Authorization | yes | **yes** | AUTHZ-001, AUTHZ-003 |
| Mass Assignment | yes | **yes** | INPUT-005 |
| Excessive Data Exposure through debug endpoint | yes | **yes** | DATA-001, DATA-003 |
| Unauthorized Password Change | yes | no | write-based BOLA (PUT): APIGuard only probes object reads, to stay non-destructive |
| SQLi Injection | no | no | injection testing is out of scope (non-destructive design) |
| User and Password Enumeration | no | no | login-response analysis not implemented |
| RegexDOS (Denial of Service) | no | no | DoS testing deliberately excluded |
| Lack of Resources & Rate Limiting | no | no | rate-limit testing excluded (request budget of 200) |
| JWT authentication bypass via weak signing key | no | no | token cryptanalysis / brute force excluded |

## Misclassifications
None: every evaluated (check, endpoint) pair matched the ground truth.

## Threats to validity
- The demo API was written by the APIGuard authors; VAmPI is included as an independent benchmark.
- Ground truth was labelled by the authors from source code; a reviewer can audit every label in `ground_truth.yaml`.
- Small sample (4 targets); results show the checks behave as designed, not general real-world detection rates.
- Detection depends on declared endpoint policies (`config/demo_targets.yaml`).
