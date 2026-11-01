import sys, os, json, sqlite3, hashlib, secrets
from datetime import datetime, timezone
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QFormLayout,
    QLabel, QLineEdit, QTextEdit, QPushButton, QTabWidget, QMessageBox, QComboBox,
    QTableWidget, QTableWidgetItem, QSpinBox, QDoubleSpinBox, QGroupBox, QInputDialog
)

APP_DIR = Path(__file__).resolve().parent
DATA_DIR = APP_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "inheritance.db"
KEY_PATH = DATA_DIR / "demo_encryption.key"

def now():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")

def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

class Store:
    def __init__(self):
        if not KEY_PATH.exists():
            KEY_PATH.write_bytes(Fernet.generate_key())
        self.fernet = Fernet(KEY_PATH.read_bytes())
        self.db = sqlite3.connect(DB_PATH)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self.init_db()

    def init_db(self):
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS wills(
          id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, owner TEXT NOT NULL,
          encrypted_content BLOB NOT NULL, content_hash TEXT NOT NULL, version INTEGER NOT NULL,
          chain_ref TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS beneficiaries(
          id INTEGER PRIMARY KEY AUTOINCREMENT, will_id INTEGER NOT NULL REFERENCES wills(id) ON DELETE CASCADE,
          name TEXT NOT NULL, contact TEXT, share REAL NOT NULL CHECK(share > 0 AND share <= 100)
        );
        CREATE TABLE IF NOT EXISTS approvers(
          id INTEGER PRIMARY KEY AUTOINCREMENT, will_id INTEGER NOT NULL REFERENCES wills(id) ON DELETE CASCADE,
          name TEXT NOT NULL UNIQUE
        );
        CREATE TABLE IF NOT EXISTS claims(
          id INTEGER PRIMARY KEY AUTOINCREMENT, will_id INTEGER NOT NULL REFERENCES wills(id),
          claimant TEXT NOT NULL, evidence_note TEXT NOT NULL, status TEXT NOT NULL,
          threshold INTEGER NOT NULL, created_at TEXT NOT NULL, released_at TEXT
        );
        CREATE TABLE IF NOT EXISTS approvals(
          id INTEGER PRIMARY KEY AUTOINCREMENT, claim_id INTEGER NOT NULL REFERENCES claims(id) ON DELETE CASCADE,
          approver TEXT NOT NULL, decision TEXT NOT NULL, reason TEXT NOT NULL, decided_at TEXT NOT NULL,
          UNIQUE(claim_id, approver)
        );
        CREATE TABLE IF NOT EXISTS assets(
          id INTEGER PRIMARY KEY AUTOINCREMENT, will_id INTEGER NOT NULL REFERENCES wills(id),
          asset_name TEXT NOT NULL, amount REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS ledger(
          id INTEGER PRIMARY KEY AUTOINCREMENT, event_type TEXT NOT NULL, record_ref TEXT NOT NULL,
          payload_hash TEXT NOT NULL, previous_hash TEXT NOT NULL, block_hash TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit(
          id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT NOT NULL, action TEXT NOT NULL,
          details TEXT NOT NULL, created_at TEXT NOT NULL
        );
        """)
        self.db.commit()

    def log(self, actor, action, details):
        self.db.execute("INSERT INTO audit(actor,action,details,created_at) VALUES(?,?,?,?)",
                        (actor, action, details, now()))
        self.db.commit()

    def anchor(self, event_type, record_ref, payload_hash):
        row = self.db.execute("SELECT block_hash FROM ledger ORDER BY id DESC LIMIT 1").fetchone()
        previous = row["block_hash"] if row else "GENESIS"
        created = now()
        block_hash = digest(f"{event_type}|{record_ref}|{payload_hash}|{previous}|{created}".encode())
        self.db.execute("""INSERT INTO ledger(event_type,record_ref,payload_hash,previous_hash,block_hash,created_at)
                           VALUES(?,?,?,?,?,?)""",
                        (event_type, str(record_ref), payload_hash, previous, block_hash, created))
        self.db.commit()
        return block_hash

    def create_will(self, title, owner, content, beneficiaries, approvers, assets):
        encoded = json.dumps(content, ensure_ascii=False, sort_keys=True).encode()
        content_hash = digest(encoded)
        encrypted = self.fernet.encrypt(encoded)
        cur = self.db.execute("""INSERT INTO wills(title,owner,encrypted_content,content_hash,version,chain_ref,created_at,updated_at)
                                 VALUES(?,?,?,?,?,?,?,?)""",
                              (title, owner, encrypted, content_hash, 1, "PENDING", now(), now()))
        wid = cur.lastrowid
        for b in beneficiaries:
            self.db.execute("INSERT INTO beneficiaries(will_id,name,contact,share) VALUES(?,?,?,?)",
                            (wid, b["name"], b["contact"], b["share"]))
        for a in approvers:
            self.db.execute("INSERT INTO approvers(will_id,name) VALUES(?,?)", (wid, a))
        for a in assets:
            self.db.execute("INSERT INTO assets(will_id,asset_name,amount) VALUES(?,?,?)",
                            (wid, a["name"], a["amount"]))
        chain_ref = self.anchor("WILL_COMMIT", wid, content_hash)
        self.db.execute("UPDATE wills SET chain_ref=? WHERE id=?", (chain_ref, wid))
        self.db.commit()
        self.log(owner, "WILL_CREATED", f"Will #{wid}; version 1; commitment {content_hash}")
        return wid

    def wills(self):
        return self.db.execute("SELECT id,title,owner,version,content_hash,chain_ref,updated_at FROM wills ORDER BY id DESC").fetchall()

    def will(self, wid):
        return self.db.execute("SELECT * FROM wills WHERE id=?", (wid,)).fetchone()

    def decrypted_content(self, wid):
        w = self.will(wid)
        if not w: raise ValueError("Will not found")
        raw = self.fernet.decrypt(w["encrypted_content"])
        return json.loads(raw.decode())

    def verify_will(self, wid):
        w = self.will(wid)
        if not w: return False, "Will not found"
        try:
            raw = self.fernet.decrypt(w["encrypted_content"])
        except InvalidToken:
            return False, "Encrypted content could not be decrypted (tampering or wrong key)."
        actual = digest(raw)
        if actual != w["content_hash"]:
            return False, f"Hash mismatch: stored {w['content_hash']}, computed {actual}"
        anchored = self.db.execute("""SELECT payload_hash FROM ledger WHERE event_type='WILL_COMMIT'
                                      AND record_ref=? ORDER BY id DESC LIMIT 1""", (str(wid),)).fetchone()
        if not anchored or anchored["payload_hash"] != actual:
            return False, "Local ledger commitment does not match the will content."
        return True, f"Integrity verified. SHA-256: {actual}"

    def create_claim(self, wid, claimant, evidence, threshold):
        cur = self.db.execute("""INSERT INTO claims(will_id,claimant,evidence_note,status,threshold,created_at)
                                 VALUES(?,?,?,'PENDING',?,?)""", (wid, claimant, evidence, threshold, now()))
        cid = cur.lastrowid
        self.anchor("CLAIM_REQUEST", cid, digest(f"{wid}|{claimant}|{evidence}|{threshold}".encode()))
        self.db.commit()
        self.log(claimant, "CLAIM_SUBMITTED", f"Claim #{cid} for will #{wid}; status PENDING")
        return cid

    def decide(self, claim_id, approver, decision, reason):
        claim = self.db.execute("SELECT * FROM claims WHERE id=?", (claim_id,)).fetchone()
        if not claim: raise ValueError("Claim not found")
        allowed = {r["name"] for r in self.db.execute("SELECT name FROM approvers WHERE will_id=?", (claim["will_id"],))}
        if approver not in allowed:
            raise ValueError(f"{approver} is not an authorized approver for this will.")
        if claim["status"] != "PENDING":
            raise ValueError(f"This claim is already {claim['status'].lower()}.")
        self.db.execute("INSERT INTO approvals(claim_id,approver,decision,reason,decided_at) VALUES(?,?,?,?,?)",
                        (claim_id, approver, decision, reason, now()))
        if decision == "REJECT":
            status = "REJECTED"
        else:
            count = self.db.execute("SELECT COUNT(*) n FROM approvals WHERE claim_id=? AND decision='APPROVE'",
                                    (claim_id,)).fetchone()["n"]
            status = "APPROVED" if count >= claim["threshold"] else "PENDING"
        self.db.execute("UPDATE claims SET status=? WHERE id=?", (status, claim_id))
        self.anchor("VERIFIER_DECISION", claim_id, digest(f"{approver}|{decision}|{reason}".encode()))
        self.db.commit()
        self.log(approver, "CLAIM_DECISION", f"Claim #{claim_id}: {decision}; {reason}; status={status}")
        if status == "APPROVED":
            self.release(claim_id)
        return status

    def release(self, claim_id):
        claim = self.db.execute("SELECT * FROM claims WHERE id=?", (claim_id,)).fetchone()
        self.db.execute("UPDATE claims SET status='RELEASED', released_at=? WHERE id=?", (now(), claim_id))
        beneficiaries = self.db.execute("SELECT name,share FROM beneficiaries WHERE will_id=? ORDER BY id",
                                        (claim["will_id"],)).fetchall()
        assets = self.db.execute("SELECT asset_name,amount FROM assets WHERE will_id=? ORDER BY id",
                                 (claim["will_id"],)).fetchall()
        receipt = {"claim_id": claim_id, "will_id": claim["will_id"], "claimant": claim["claimant"],
                   "beneficiary_allocations": [{"name": b["name"], "share_percent": b["share"]} for b in beneficiaries],
                   "test_assets": [{"asset": a["asset_name"], "total": a["amount"],
                                   "allocations": [{"beneficiary": b["name"], "amount": round(a["amount"]*b["share"]/100, 8)}
                                                   for b in beneficiaries]} for a in assets],
                   "notice": "SIMULATED TEST-ASSET RELEASE ONLY; no real funds were transferred."}
        h = digest(json.dumps(receipt, sort_keys=True).encode())
        self.anchor("DEMO_RELEASE", claim_id, h)
        self.db.commit()
        self.log("SYSTEM", "DEMO_RELEASE", json.dumps(receipt, ensure_ascii=False))
        return receipt

    def claims(self):
        return self.db.execute("""SELECT c.*,w.title FROM claims c JOIN wills w ON w.id=c.will_id ORDER BY c.id DESC""").fetchall()

    def audit_rows(self):
        return self.db.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 500").fetchall()

    def ledger_rows(self):
        return self.db.execute("SELECT * FROM ledger ORDER BY id DESC LIMIT 500").fetchall()

    def verify_ledger(self):
        rows = self.db.execute("SELECT * FROM ledger ORDER BY id").fetchall()
        previous = "GENESIS"
        for r in rows:
            expected = digest(f"{r['event_type']}|{r['record_ref']}|{r['payload_hash']}|{previous}|{r['created_at']}".encode())
            if r["previous_hash"] != previous or r["block_hash"] != expected:
                return False, f"Ledger chain broken at entry #{r['id']}."
            previous = r["block_hash"]
        return True, f"Local hash-linked ledger verified ({len(rows)} entries)."

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.store = Store()
        self.setWindowTitle("Digital Will & Inheritance — PyQt6 Academic Prototype")
        self.resize(1180, 800)
        self.setStyleSheet("""
          QMainWindow, QWidget { background:#101827; color:#e8eef8; font-size:13px; }
          QTabWidget::pane { border:1px solid #334155; }
          QTabBar::tab { background:#1e293b; padding:10px 15px; margin:2px; border-radius:5px; }
          QTabBar::tab:selected { background:#2563eb; }
          QLineEdit, QTextEdit, QComboBox, QSpinBox, QDoubleSpinBox { background:#0b1220; border:1px solid #475569; border-radius:4px; padding:7px; color:#f8fafc; }
          QPushButton { background:#2563eb; border:0; border-radius:5px; padding:9px 13px; color:white; font-weight:bold; }
          QPushButton:hover { background:#3b82f6; }
          QTableWidget { background:#0b1220; gridline-color:#334155; alternate-background-color:#172033; }
          QHeaderView::section { background:#1e293b; padding:6px; border:0; }
          QGroupBox { border:1px solid #334155; margin-top:10px; padding:10px; font-weight:bold; }
          QLabel#muted { color:#a8b5c9; }
        """)
        root = QWidget(); layout = QVBoxLayout(root)
        heading = QLabel("BLOCKCHAIN-BASED DIGITAL WILL & INHERITANCE SYSTEM")
        heading.setStyleSheet("font-size:20px;font-weight:800;color:#93c5fd;padding:8px")
        sub = QLabel("Encrypted records • SHA-256 commitment • Multi-approval • Auditable demo release")
        sub.setObjectName("muted")
        layout.addWidget(heading); layout.addWidget(sub)
        self.tabs = QTabWidget()
        self.tabs.addTab(self.owner_tab(), "Owner Dashboard")
        self.tabs.addTab(self.beneficiary_tab(), "Beneficiary Portal")
        self.tabs.addTab(self.verifier_tab(), "Verifier Console")
        self.tabs.addTab(self.audit_tab(), "Audit & Integrity")
        layout.addWidget(self.tabs)
        self.setCentralWidget(root)
        self.refresh_all()

    def table(self, headers):
        t = QTableWidget(0, len(headers)); t.setHorizontalHeaderLabels(headers)
        t.setAlternatingRowColors(True); t.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        t.horizontalHeader().setStretchLastSection(True)
        return t

    def selected_id(self, table, col=0):
        row = table.currentRow()
        if row < 0: return None
        item = table.item(row, col)
        try: return int(item.text().lstrip("#"))
        except Exception: return None

    def owner_tab(self):
        w = QWidget(); l = QVBoxLayout(w)
        formbox = QGroupBox("Create a new encrypted digital will"); form = QFormLayout(formbox)
        self.owner = QLineEdit("Owner Demo"); self.title = QLineEdit("My Digital Inheritance Plan")
        self.instructions = QTextEdit()
        self.instructions.setPlaceholderText("Private instructions, digital asset notes, recovery guidance (demo data only)…")
        self.instructions.setMaximumHeight(95)
        self.beneficiaries = QTextEdit("Alex Demo,alex@example.test,60\nJordan Demo,jordan@example.test,40")
        self.beneficiaries.setPlaceholderText("One beneficiary per line: Name,contact,share_percent")
        self.beneficiaries.setMaximumHeight(90)
        self.approvers = QLineEdit("Verifier One,Verifier Two,Verifier Three")
        self.threshold = QSpinBox(); self.threshold.setRange(1, 10); self.threshold.setValue(2)
        self.assets = QTextEdit("Demo Token,100\nDemo Credits,50")
        self.assets.setMaximumHeight(65)
        form.addRow("Owner display name", self.owner); form.addRow("Will title", self.title)
        form.addRow("Private will instructions", self.instructions)
        form.addRow("Beneficiaries (name,contact,share %)", self.beneficiaries)
        form.addRow("Authorized approvers (comma-separated)", self.approvers)
        form.addRow("Required approvals", self.threshold)
        form.addRow("Test assets (name,amount)", self.assets)
        l.addWidget(formbox)
        btn = QPushButton("Encrypt, Save & Anchor Commitment"); btn.clicked.connect(self.create_will); l.addWidget(btn)
        self.wills_table = self.table(["ID", "Title", "Owner", "Version", "Content SHA-256", "Local chain ref", "Updated"])
        l.addWidget(QLabel("Saved will records (select a row to inspect / verify)")); l.addWidget(self.wills_table)
        row = QHBoxLayout()
        b1 = QPushButton("Verify Selected Will"); b1.clicked.connect(self.verify_selected_will)
        b2 = QPushButton("View Decrypted Details"); b2.clicked.connect(self.view_selected_will)
        row.addWidget(b1); row.addWidget(b2); l.addLayout(row)
        return w

    def beneficiary_tab(self):
        w = QWidget(); l = QVBoxLayout(w)
        box = QGroupBox("Submit a claim request"); f = QFormLayout(box)
        self.claim_will = QComboBox(); self.claimant = QLineEdit("Alex Demo")
        self.evidence = QTextEdit("Demo evidence reviewed outside this application; reference: DEMO-001")
        self.evidence.setMaximumHeight(80)
        self.claim_threshold = QSpinBox(); self.claim_threshold.setRange(1, 10); self.claim_threshold.setValue(2)
        f.addRow("Will", self.claim_will); f.addRow("Claimant / beneficiary", self.claimant)
        f.addRow("Evidence note (do not enter sensitive real IDs)", self.evidence)
        f.addRow("Approval threshold", self.claim_threshold)
        l.addWidget(box)
        b = QPushButton("Submit Claim"); b.clicked.connect(self.submit_claim); l.addWidget(b)
        self.claims_table = self.table(["Claim ID", "Will", "Claimant", "Status", "Threshold", "Created"])
        l.addWidget(QLabel("Claim status and simulated release results")); l.addWidget(self.claims_table)
        self.release_view = QTextEdit(); self.release_view.setReadOnly(True); self.release_view.setMaximumHeight(150)
        l.addWidget(self.release_view)
        return w

    def verifier_tab(self):
        w = QWidget(); l = QVBoxLayout(w)
        note = QLabel("Choose the verifier name configured for the selected will. A rejection stops the claim.")
        note.setObjectName("muted"); l.addWidget(note)
        self.verifier_claims = self.table(["Claim ID", "Will", "Claimant", "Status", "Threshold", "Created"])
        l.addWidget(self.verifier_claims)
        row = QHBoxLayout()
        self.verifier_name = QComboBox()
        self.verifier_decision = QComboBox(); self.verifier_decision.addItems(["APPROVE", "REJECT"])
        row.addWidget(QLabel("Authorized verifier")); row.addWidget(self.verifier_name)
        row.addWidget(QLabel("Decision")); row.addWidget(self.verifier_decision)
        l.addLayout(row)
        self.reason = QLineEdit("Reviewed demo evidence")
        l.addWidget(QLabel("Decision reason")); l.addWidget(self.reason)
        btn = QPushButton("Record Decision"); btn.clicked.connect(self.record_decision); l.addWidget(btn)
        return w

    def audit_tab(self):
        w = QWidget(); l = QVBoxLayout(w)
        row = QHBoxLayout()
        b1 = QPushButton("Verify All Will Hashes"); b1.clicked.connect(self.verify_all)
        b2 = QPushButton("Verify Hash-Linked Ledger"); b2.clicked.connect(self.verify_ledger)
        b3 = QPushButton("Refresh Audit"); b3.clicked.connect(self.refresh_all)
        row.addWidget(b1); row.addWidget(b2); row.addWidget(b3); l.addLayout(row)
        self.integrity_result = QLabel("Integrity checks have not been run.")
        self.integrity_result.setWordWrap(True); l.addWidget(self.integrity_result)
        l.addWidget(QLabel("Local ledger (simulated blockchain commitment log)"))
        self.ledger_table = self.table(["ID", "Event", "Record", "Payload hash", "Previous hash", "Block hash", "Time"])
        l.addWidget(self.ledger_table)
        l.addWidget(QLabel("Application audit trail"))
        self.audit_table = self.table(["ID", "Actor", "Action", "Details", "Time"])
        l.addWidget(self.audit_table)
        return w

    def parse_lines(self, text, fields, label):
        result = []
        for i, line in enumerate(text.strip().splitlines(), 1):
            if not line.strip(): continue
            parts = [x.strip() for x in line.split(",")]
            if len(parts) != fields: raise ValueError(f"{label}, line {i}: expected {fields} comma-separated fields.")
            result.append(parts)
        return result

    def create_will(self):
        try:
            owner = self.owner.text().strip(); title = self.title.text().strip()
            if not owner or not title: raise ValueError("Owner and title are required.")
            bs = self.parse_lines(self.beneficiaries.toPlainText(), 3, "Beneficiary")
            if not bs: raise ValueError("Add at least one beneficiary.")
            beneficiaries = [{"name": n, "contact": c, "share": float(s)} for n,c,s in bs]
            if any(not b["name"] or b["share"] <= 0 for b in beneficiaries): raise ValueError("Beneficiary names and shares must be valid.")
            total = sum(b["share"] for b in beneficiaries)
            if abs(total-100) > 0.0001: raise ValueError(f"Beneficiary shares must total exactly 100% (currently {total:g}%).")
            approvers = list(dict.fromkeys(x.strip() for x in self.approvers.text().split(",") if x.strip()))
            if not approvers: raise ValueError("Add at least one approver.")
            if self.threshold.value() > len(approvers): raise ValueError("Required approvals cannot exceed the number of approvers.")
            assets = []
            for n,a in self.parse_lines(self.assets.toPlainText(), 2, "Asset"):
                amount = float(a)
                if not n or amount < 0: raise ValueError("Test asset names and amounts must be valid.")
                assets.append({"name":n, "amount":amount})
            content = {"owner":owner, "title":title, "instructions":self.instructions.toPlainText(),
                       "beneficiaries":beneficiaries, "approvers":approvers, "approval_threshold":self.threshold.value(),
                       "test_assets":assets, "scope":"Academic demo only; not a legally executed will."}
            wid = self.store.create_will(title, owner, content, beneficiaries, approvers, assets)
            QMessageBox.information(self, "Saved", f"Will #{wid} encrypted and saved. A SHA-256 commitment was added to the local hash-linked ledger.")
            self.refresh_all()
        except Exception as e: QMessageBox.warning(self, "Could not create will", str(e))

    def verify_selected_will(self):
        wid = self.selected_id(self.wills_table)
        if wid is None: QMessageBox.information(self, "Select a will", "Select a will row first."); return
        ok, msg = self.store.verify_will(wid)
        self.integrity_result.setText(("✓ " if ok else "✗ ") + msg)
        QMessageBox.information(self, "Integrity check", msg)

    def view_selected_will(self):
        wid = self.selected_id(self.wills_table)
        if wid is None: QMessageBox.information(self, "Select a will", "Select a will row first."); return
        try:
            content = self.store.decrypted_content(wid)
            QMessageBox.information(self, "Decrypted will (local demo)", json.dumps(content, indent=2, ensure_ascii=False))
            self.store.log(content.get("owner","Owner"), "WILL_VIEWED", f"Decrypted will #{wid} viewed locally")
            self.refresh_all()
        except Exception as e: QMessageBox.warning(self, "Cannot decrypt", str(e))

    def submit_claim(self):
        try:
            wid = self.claim_will.currentData()
            if wid is None: raise ValueError("Create a will first.")
            claimant = self.claimant.text().strip(); evidence = self.evidence.toPlainText().strip()
            if not claimant or not evidence: raise ValueError("Claimant and evidence note are required.")
            content = self.store.decrypted_content(wid)
            threshold = self.claim_threshold.value()
            if threshold > len(content["approvers"]): raise ValueError("Threshold exceeds the number of authorized approvers.")
            cid = self.store.create_claim(wid, claimant, evidence, threshold)
            QMessageBox.information(self, "Claim submitted", f"Claim #{cid} submitted. Authorized verifiers must approve it before a simulated release.")
            self.refresh_all()
        except Exception as e: QMessageBox.warning(self, "Could not submit claim", str(e))

    def record_decision(self):
        cid = self.selected_id(self.verifier_claims)
        if cid is None: QMessageBox.information(self, "Select a claim", "Select a claim row first."); return
        name = self.verifier_name.currentText()
        if not name: QMessageBox.warning(self, "No verifier", "No configured approvers are available."); return
        try:
            status = self.store.decide(cid, name, self.verifier_decision.currentText(), self.reason.text().strip())
            QMessageBox.information(self, "Decision recorded", f"Claim #{cid} status: {status}")
            if status == "RELEASED":
                receipt = self.store.release_receipt if hasattr(self.store, "release_receipt") else None
            self.refresh_all()
        except Exception as e: QMessageBox.warning(self, "Decision failed", str(e))

    def verify_all(self):
        wills = self.store.wills()
        results = [self.store.verify_will(w["id"]) for w in wills]
        bad = [m for ok,m in results if not ok]
        self.integrity_result.setText("✓ All will commitments verified." if not bad else "✗ " + " | ".join(bad))
        self.store.log("SYSTEM", "BULK_INTEGRITY_CHECK", f"Checked {len(wills)} will(s); failures={len(bad)}")
        self.refresh_all()

    def verify_ledger(self):
        ok, msg = self.store.verify_ledger()
        self.integrity_result.setText(("✓ " if ok else "✗ ") + msg)
        self.store.log("SYSTEM", "LEDGER_INTEGRITY_CHECK", msg)
        self.refresh_all()

    def refresh_all(self):
        if not hasattr(self, "wills_table"): return
        wills = self.store.wills()
        self.wills_table.setRowCount(0)
        self.claim_will.clear()
        for w in wills:
            row = self.wills_table.rowCount(); self.wills_table.insertRow(row)
            vals = [w["id"], w["title"], w["owner"], w["version"], w["content_hash"][:18]+"…", w["chain_ref"][:18]+"…", w["updated_at"]]
            for c,v in enumerate(vals): self.wills_table.setItem(row,c,QTableWidgetItem(str(v)))
            self.claim_will.addItem(f"#{w['id']} — {w['title']}", w["id"])
        claims = self.store.claims()
        for table in (self.claims_table, self.verifier_claims):
            table.setRowCount(0)
            for c in claims:
                row=table.rowCount(); table.insertRow(row)
                vals=[c["id"],c["title"],c["claimant"],c["status"],c["threshold"],c["created_at"]]
                for col,v in enumerate(vals): table.setItem(row,col,QTableWidgetItem(str(v)))
        self.verifier_name.clear()
        current_claim_id = self.selected_id(self.verifier_claims)
        selected_claim = next((c for c in claims if c["id"] == current_claim_id), claims[0] if claims else None)
        if selected_claim:
            rows = self.store.db.execute("SELECT name FROM approvers WHERE will_id=?", (selected_claim["will_id"],)).fetchall()
            self.verifier_name.addItems([r["name"] for r in rows])
        self.ledger_table.setRowCount(0)
        for r in self.store.ledger_rows():
            row=self.ledger_table.rowCount(); self.ledger_table.insertRow(row)
            vals=[r["id"],r["event_type"],r["record_ref"],r["payload_hash"][:16]+"…",r["previous_hash"][:16]+"…",r["block_hash"][:16]+"…",r["created_at"]]
            for col,v in enumerate(vals): self.ledger_table.setItem(row,col,QTableWidgetItem(str(v)))
        self.audit_table.setRowCount(0)
        for r in self.store.audit_rows():
            row=self.audit_table.rowCount(); self.audit_table.insertRow(row)
            vals=[r["id"],r["actor"],r["action"],r["details"],r["created_at"]]
            for col,v in enumerate(vals): self.audit_table.setItem(row,col,QTableWidgetItem(str(v)))
        self.release_view.setPlainText("Latest released claim receipt is recorded in the audit trail. All asset amounts are simulated test units; no transfer occurs.")
        self.wills_table.resizeColumnsToContents(); self.claims_table.resizeColumnsToContents()
        self.verifier_claims.resizeColumnsToContents(); self.ledger_table.resizeColumnsToContents(); self.audit_table.resizeColumnsToContents()

def main():
    app = QApplication(sys.argv)
    window = MainWindow(); window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
