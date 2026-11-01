# Blockchain-Based Digital Will & Inheritance System (PyQt6)

A desktop academic prototype based on the supplied presentation. It demonstrates:
- Owner dashboard for structured will creation.
- Fernet authenticated encryption for private will contents stored in SQLite.
- SHA-256 content commitment and a local hash-linked ledger (simulated blockchain).
- Beneficiary records and share validation (must total 100%).
- Configurable authorized approvers and multi-approval threshold.
- Claim submission with an evidence note, verifier approve/reject decisions, and conditional demo release.
- Simulated test assets distributed by beneficiary percentage.
- Audit trail, per-will integrity verification, and ledger-chain verification.

## Run on Windows
1. Install Python 3.10 or newer.
2. Extract this ZIP.
3. Double-click `run_windows.bat`, or run:
   ```powershell
   py -m pip install -r requirements.txt
   py main.py
   ```
The first launch creates `data/inheritance.db` and `data/demo_encryption.key`. Keep the key file safe: if it is lost, encrypted will contents cannot be decrypted. This local demo key management is not production-grade.

## Suggested demo
1. In Owner Dashboard, edit the owner/title/instructions.
2. Add beneficiaries, one per line: `Name,contact,share_percent`. Shares must total 100.
3. Set approvers as comma-separated names, e.g. `Verifier One,Verifier Two,Verifier Three`; set required approvals to 2.
4. Add test assets, one per line: `Demo Token,100`.
5. Click **Encrypt, Save & Anchor Commitment**.
6. Open Beneficiary Portal and submit a claim for the will.
7. Open Verifier Console, select the claim, choose an authorized verifier, enter a reason, and record APPROVE. Repeat with a different authorized verifier until the threshold is met. A REJECT decision rejects the claim.
8. Open Audit & Integrity and verify will hashes and the local ledger.

## Important prototype limitations
- This is a **local simulation**, not a deployed blockchain or Solidity smart contract. The ledger is hash-linked in SQLite and can be edited by someone with direct database access.
- Test-asset release is a receipt and calculation only; no real token, wallet, or funds are transferred.
- The app cannot determine whether someone has died. Evidence is only a manually entered note; there is no official verifier integration or appeal process.
- The encryption key is stored beside the database for easy classroom demonstration. Real deployment needs secure key custody/recovery, hardened authentication, role enforcement, independent security review, and legal review.
- Do not enter real identity numbers, seed phrases, private keys, or sensitive personal data. This is not a legally valid will service.

## Project structure
- `main.py` — PyQt6 desktop app and workflow logic
- `requirements.txt` — dependencies
- `run_windows.bat` — install and launch helper
- `data/` — database and key are generated on first run
