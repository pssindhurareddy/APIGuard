# Test evidence

Raw evidence for the test cases in the *APIGuard Test Evidence* document (TC-01 to TC-08),
captured on 2026-10-30 from the submission build.

| File | Test case |
| --- | --- |
| tc01_bola_vulnerable.txt, fig1_bola_finding.png | TC-01 BOLA detected (demo API, vulnerable) |
| tc02_bola_secure.txt, fig2_dashboard_overview.png | TC-02 BOLA prevented (demo API, secure; 44/44 PASS) |
| tc03_vampi_mass_assignment.txt, fig3_vampi_mass_assignment.png | TC-03 Verified mass assignment (VAmPI) |
| tc04_vampi_debug_leak.txt, fig4_vampi_debug_leak.png | TC-04 Password leak persists in VAmPI secure mode |
| tc05_scopeguard.txt | TC-05 ScopeGuard blocks out-of-scope targets |
| tc06_redaction.txt | TC-06 No secrets in 157 stored findings |
| tc07_remediation_comparison.txt, fig5_comparison_demo.png, fig6_comparison_vampi.png | TC-07 Before/after comparison |
| tc08_pytest_full.txt | TC-08 Full automated suite (54 passed) |
| scan_results_all_targets.txt | Per-check results of all four scans |

The accuracy evaluation report is in `../evaluation/results/evaluation_report.md`.
