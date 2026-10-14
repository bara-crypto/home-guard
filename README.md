# HomeGuard AI — prototype (Step 1)

Detects three network attacks — **port scan, brute force, DoS** — from network-flow
metadata, using a Random Forest trained on flow features. Includes a client/victim
agent and a bounded, lab-only traffic generator so you can produce your own training
data and run a live detection demo across three laptops.

Classes: `benign`, `portscan`, `bruteforce`, `dos`.

## Lab layout

- **Laptop A** — client/victim: runs the target services + the HomeGuard agent
  (sniffer + model). See `docs/CLIENT_SETUP.md`.
- **Laptop B** — hacker: runs `hacker/hacker_intent.py` against A only.
  See `docs/HACKER_SETUP.md`.
- **Laptop C** — dev/trainer: download data, train models, build later steps.

## Layout

```
homeguard/
├─ data/raw/         # public dataset (HF parquet) — gitignored
│  ├─ captured/      # your lab pcaps + flow CSVs, one folder per class — gitignored
│  └─ processed/     # train/test parquet — gitignored
├─ models/           # rf_v1.joblib + features.json (live), rf_phaseA.* — gitignored
├─ reports/          # metrics, confusion matrices, column lists
├─ src/              # 01_download, 02_explore, 03_learn_features, 03_train, 04_train_lab, trainer
├─ lab/              # capture.py, convert.py, run_cicflowmeter.py (extractor wrapper)
├─ agent/            # api.py, run_agent.py, infer.py  (Laptop A)
├─ client/           # client_intent.py  (Laptop A, standalone)
├─ hacker/           # hacker_intent.py  (Laptop B, standalone, copyable alone)
├─ tests/            # verify_client.py, verify_hacker.py
└─ docs/             # CLIENT_SETUP, HACKER_SETUP, TEST_PLAN
```

## Quick start (dev machine)

```bash
python -m venv .venv
# Windows:  .venv\Scripts\activate       Linux/macOS:  source .venv/bin/activate
pip install -r requirements.txt

# Phase A — validate the pipeline on the public dataset
python src/01_download.py              # downloads CIC-IDS2017 Network-Flows (~370 MB)
python src/02_explore.py               # columns + label counts -> reports/
python src/03_learn_features.py        # live cicflowmeter feature names + overlap
python src/03_train.py                 # Phase A model (pipeline proof, NOT deployed)

# Phase B — the model you actually deploy (needs your own captures; see docs/TEST_PLAN.md)
python src/04_train_lab.py --demo      # synthetic smoke test, no captures needed
python src/04_train_lab.py             # real lab flows -> models/rf_v1.joblib
```

## Two phases, one deployed model

- **Phase A** (`src/03_train.py`) trains on the public **CIC-IDS2017** dataset. It proves
  the pipeline but is trained on a *different* flow extractor's features, so it is **not**
  deployed live.
- **Phase B** (`src/04_train_lab.py`) trains on flows you capture in your own lab with the
  **same** extractor that runs live (`lab/run_cicflowmeter.py`). Its output,
  `models/rf_v1.joblib`, is the **live** model.

## Known tooling note

The published `cicflowmeter` 0.5.0 **CLI** mispasses its own arguments and crashes on
both `-f` and `-i`. HomeGuard therefore calls the same library through
`lab/run_cicflowmeter.py`, which passes arguments by keyword. Use that wrapper, not the
bare `cicflowmeter` command. If a later release fixes the CLI, callers can switch back
with no other changes.

## Verify

```bash
python tests/verify_client.py    # serve + agent + /predict + benign + live path + teardown
python tests/verify_hacker.py    # phases vs loopback + guard refusals + teardown
```

## Safety

`hacker/hacker_intent.py` only runs against loopback / RFC1918 private IPs, requires
`--confirm-lab`, caps duration at 120 s, uses a dummy FTP wordlist that excludes the real
lab password, and bounds the DoS load. It has no exploits and no evasion. Keep it pointed
at your own lab only.
