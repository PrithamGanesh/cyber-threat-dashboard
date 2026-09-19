"""Unified Test Runner and Reporting Utility for LiveSOC.

Executes:
1. Regression Testing Suite
2. End-to-End (E2E) Testing Suite
3. Performance & Concurrency Load Benchmarks
4. Frontend Build & Asset Verification
"""
import sys
import subprocess
import time
import os

# Ensure safe encoding on Windows console
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

def run_step(title: str, command: list, cwd: str = None) -> bool:
    print(f"\n{'='*70}")
    print(f"[RUNNING] {title}")
    print(f"Command: {' '.join(command)}")
    print(f"{'='*70}\n")
    t0 = time.time()
    result = subprocess.run(command, cwd=cwd)
    t1 = time.time()
    duration = round(t1 - t0, 2)
    if result.returncode == 0:
        print(f"\n[PASSED] {title} (in {duration}s)")
        return True
    else:
        print(f"\n[FAILED] {title} (exit code {result.returncode}, in {duration}s)")
        return False

def main():
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    python_bin = os.path.join(root_dir, ".venv", "Scripts", "python.exe")
    pytest_bin = os.path.join(root_dir, ".venv", "Scripts", "pytest.exe")
    
    if not os.path.exists(pytest_bin):
        pytest_bin = "pytest"
    if not os.path.exists(python_bin):
        python_bin = "python"

    results = {}

    # 1. Regression Tests
    results["Regression Testing"] = run_step(
        "Regression Test Suite (Security, Parsers, Scoring, CRUD)",
        [pytest_bin, "-v", "tests/test_regression.py"],
        cwd=root_dir
    )

    # 2. E2E Tests
    results["E2E Testing"] = run_step(
        "End-to-End (E2E) Full Lifecycle Tests",
        [pytest_bin, "-v", "tests/test_e2e.py"],
        cwd=root_dir
    )

    # 3. Performance Tests
    results["Performance Testing"] = run_step(
        "Performance & Concurrency Load Benchmarks",
        [pytest_bin, "-v", "-s", "tests/test_performance.py"],
        cwd=root_dir
    )

    # 4. Frontend Build Verification
    frontend_dir = os.path.join(root_dir, "frontend")
    results["Frontend Build Verification"] = run_step(
        "Frontend Vite Production Bundle Build",
        ["npm.cmd" if os.name == "nt" else "npm", "run", "build"],
        cwd=frontend_dir
    )

    # Final Summary Table
    print(f"\n\n{'='*70}")
    print("TEST EXECUTION SUMMARY")
    print(f"{'='*70}")
    all_passed = True
    for test_name, passed in results.items():
        status_symbol = "[PASSED]" if passed else "[FAILED]"
        print(f" - {test_name.ljust(35)} : {status_symbol}")
        if not passed:
            all_passed = False
    print(f"{'='*70}")

    if all_passed:
        print("\nALL TEST SUITES PASSED SUCCESSFULLY!\n")
        sys.exit(0)
    else:
        print("\nSOME TEST SUITES FAILED. PLEASE REVIEW LOGS ABOVE.\n")
        sys.exit(1)

if __name__ == "__main__":
    main()
