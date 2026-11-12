"""Détection d'anomalies de FLAIR Sentinel.

Chaîne : télémétrie brute -> variables numériques -> score Isolation Forest
(machine learning, non supervisé) -> règles explicables qui donnent une
HYPOTHÈSE et un verdict -> regroupement des messages en alertes.

Le ML hiérarchise et attrape l'inattendu ; les règles typent et expliquent.
Aucune étiquette de référence n'est utilisée ici (seulement dans evaluate_*).
"""

import json

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from config import (
    EVENTS_FILE, INVENTORY_FILE, LABELS_FILE, PLANNING_FILE, SCENARIOS_FILE,
)
from securite import detecter_injection

# =====================================================
# PARAMÈTRES (documentés dans knowledge/KB-07)
# =====================================================

PHYS_RANGE = {"temperature": (-10, 50), "humidity": (0, 100), "co2": (350, 5000)}
NOISE_FLOOR = {"temperature": 0.15, "humidity": 0.8, "co2": 30}

SILENCE_MIN_CYCLES = 3      # 15 min
STUCK_MIN_REPEAT = 12       # même valeur 12 fois de suite = 1 h
DRIFT_WINDOW = 24           # 2 h de messages
DRIFT_THRESHOLD = 1.0       # °C d'écart moyen à la médiane de la salle
REPLAY_DELAY_MIN = 5       # un cycle de mesure
SPIKE_Z = 6
CLONE_WINDOW_MIN = 15
SEQ_WINDOW = "20min"
ML_CONTAMINATION = 0.01
ALERT_GAP_MIN = 30
PLAN_GRACE_MIN = 30

HYPOTHESES = {
    "normal": "Normal",
    "sensor_failure": "Panne possible",
    "drift": "Dérive possible",
    "possible_clone": "Clonage possible",
    "buffer_replay": "Rejeu de tampon",
    "planned_event": "Maintenance / événement planifié",
    "unknown": "Anomalie non typée",
}
VERDICTS = {
    "a_traiter": "À traiter",
    "probablement_normal": "Probablement normal",
    "normal": "Normal",
}
SEVERITY_WEIGHT = {"Élevé": 60, "Modéré": 40, "Faible": 20}
INCIDENT_LABELS = ["sensor_failure", "drift", "possible_clone"]

ML_FEATURES = [
    "f_abs_z", "f_level", "f_dev", "f_delay", "f_gap", "f_missing",
    "f_silence", "f_oor", "f_stuck", "f_mac", "f_seq",
]

# =====================================================
# CHARGEMENT
# =====================================================

def load_data():
    events = pd.read_csv(
        EVENTS_FILE, encoding="utf-8-sig",
        dtype={"device_msg": str, "mac": str, "ip": str, "firmware": str},
        keep_default_na=False, na_values={"value": [""], "seq": [""]},
    )
    for col in ("timestamp", "measurement_timestamp"):
        events[col] = pd.to_datetime(events[col], utc=True, format="ISO8601")
    events["value"] = pd.to_numeric(events["value"], errors="coerce")
    events["seq"] = pd.to_numeric(events["seq"], errors="coerce")
    events["battery_pct"] = pd.to_numeric(events["battery_pct"], errors="coerce")
    events["rssi_dbm"] = pd.to_numeric(events["rssi_dbm"], errors="coerce")

    inventory = pd.read_csv(INVENTORY_FILE, encoding="utf-8-sig")

    with PLANNING_FILE.open(encoding="utf-8") as f:
        planning = json.load(f)
    for p in planning:
        p["debut_ts"] = pd.Timestamp(p["debut"])
        p["fin_ts"] = pd.Timestamp(p["fin"])

    references = (pd.read_csv(LABELS_FILE, encoding="utf-8-sig")
                  if LABELS_FILE.exists() else pd.DataFrame())
    scenarios = []
    if SCENARIOS_FILE.exists():
        with SCENARIOS_FILE.open(encoding="utf-8") as f:
            scenarios = json.load(f)

    return {"raw": events, "inventory": inventory, "planning": planning,
            "references": references, "scenarios": scenarios}


# =====================================================
# VARIABLES NUMÉRIQUES
# =====================================================

def _run_length(df, flag, key):
    """Longueur de la série consécutive de `key` identiques (par capteur)."""
    change = (df[key] != df.groupby("sensor_id")[key].shift()) | \
             (df["sensor_id"] != df["sensor_id"].shift())
    block = change.cumsum()
    size = df.groupby(block)[key].transform("size")
    return size.where(flag, 0)


def compute_features(events, inventory):
    df = events.sort_values(["sensor_id", "timestamp", "event_id"]).reset_index(drop=True)

    df["delay_min"] = (df["timestamp"] - df["measurement_timestamp"]).dt.total_seconds() / 60
    df["gap_rx_min"] = df.groupby("sensor_id")["timestamp"].diff().dt.total_seconds() / 60
    df["missing"] = df["value"].isna()

    lo = df["sensor_type"].map(lambda t: PHYS_RANGE[t][0])
    hi = df["sensor_type"].map(lambda t: PHYS_RANGE[t][1])
    df["out_of_range"] = df["value"].notna() & ((df["value"] < lo) | (df["value"] > hi))

    # Silence : nombre de no_data consécutifs
    df["silence_run"] = _run_length(df, df["missing"], "missing")

    # Valeur figée : même valeur répétée
    df["_val_key"] = df["value"].fillna(-99999)
    df["identical_run"] = _run_length(df, ~df["missing"], "_val_key")

    # --- Identité : MAC inconnue, séquences qui reculent, firmware ---
    expected_mac = inventory.set_index("sensor_id")["mac"]
    df["mac_unknown"] = (df["mac"] != "") & (df["mac"] != df["sensor_id"].map(expected_mac))
    df["clone_window"] = False
    for sid, grp in df[df["mac_unknown"]].groupby("sensor_id"):
        # Causal : une MAC inconnue a été vue dans les 15 dernières minutes
        times = grp["timestamp"].values
        mask = df["sensor_id"] == sid
        t = df.loc[mask, "timestamp"].values
        j = np.searchsorted(times, t, side="right") - 1
        seen = j >= 0
        last = times[np.clip(j, 0, None)]
        df.loc[mask, "clone_window"] = seen & (t - last <= np.timedelta64(CLONE_WINDOW_MIN, "m"))

    # --- Séries de valeurs valides, dans l'ordre des mesures ---
    # (les messages d'une MAC inconnue ne servent pas de référence)
    valid = df[~df["missing"] & ~df["out_of_range"] & ~df["mac_unknown"]].sort_values(
        ["sensor_id", "measurement_timestamp"])
    floor = valid["sensor_type"].map(NOISE_FLOOR)
    g = valid.groupby("sensor_id")["value"]
    med = g.transform(lambda s: s.rolling(12, min_periods=6).median().shift(1))
    std = g.transform(lambda s: s.rolling(12, min_periods=6).std().shift(1))
    valid["z_self"] = (valid["value"] - med) / np.maximum(std.fillna(0), floor)

    sensor_med = g.transform("median")
    q75 = g.transform(lambda s: s.quantile(0.75))
    q25 = g.transform(lambda s: s.quantile(0.25))
    valid["level_z"] = (valid["value"] - sensor_med) / np.maximum(q75 - q25, floor)

    # Écart à la médiane de la salle (températures : 3 sondes par salle)
    valid["slot"] = valid["measurement_timestamp"].dt.floor("5min")
    room_med = valid.groupby(["room", "sensor_type", "slot"])["value"].transform("median")
    room_n = valid.groupby(["room", "sensor_type", "slot"])["value"].transform("size")
    valid["dev_room"] = np.where(
        (valid["sensor_type"] == "temperature") & (room_n >= 3),
        valid["value"] - room_med, np.nan)
    valid["dev_room_smooth"] = valid.groupby("sensor_id")["dev_room"].transform(
        lambda s: s.rolling(DRIFT_WINDOW, min_periods=12).mean())

    df = df.merge(valid[["event_id", "z_self", "level_z", "dev_room", "dev_room_smooth"]],
                  on="event_id", how="left")

    seq_prev = df[~df["missing"]].groupby("sensor_id")["seq"].shift()
    df["seq_back"] = False
    df.loc[seq_prev.index, "seq_back"] = (df.loc[seq_prev.index, "seq"] < seq_prev).values
    df["seq_back_win"] = (
        df.set_index("timestamp").groupby("sensor_id")["seq_back"]
        .rolling(SEQ_WINDOW).sum().reset_index(level=0, drop=True).values
    )
    fw_prev = df[~df["missing"]].groupby("sensor_id")["firmware"].shift()
    df["fw_change"] = False
    df.loc[fw_prev.index, "fw_change"] = (
        fw_prev.notna() & (df.loc[fw_prev.index, "firmware"] != fw_prev)).values

    df["replay"] = (df["delay_min"] >= REPLAY_DELAY_MIN) & (df["network_status"] == "reconnected")
    df["injection"] = df["device_msg"].map(lambda m: bool(m) and detecter_injection(m)[0])

    # --- Variables pour le modèle ML (sans unité, comparables entre capteurs) ---
    df["f_abs_z"] = df["z_self"].abs().clip(0, 30).fillna(0)
    df["f_level"] = df["level_z"].abs().clip(0, 30).fillna(0)
    df["f_dev"] = df["dev_room_smooth"].abs().fillna(0)
    df["f_delay"] = np.log1p(df["delay_min"].clip(lower=0))
    df["f_gap"] = np.abs(np.log(df["gap_rx_min"].clip(lower=0.05).fillna(5) / 5))
    df["f_missing"] = df["missing"].astype(int)
    df["f_silence"] = np.log1p(df["silence_run"])
    df["f_oor"] = df["out_of_range"].astype(int)
    df["f_stuck"] = np.log1p(df["identical_run"].where(df["identical_run"] > 2, 0))
    df["f_mac"] = (df["mac_unknown"] | df["clone_window"]).astype(int)
    df["f_seq"] = df["seq_back_win"].clip(0, 10)

    return df.drop(columns="_val_key")


# =====================================================
# MODÈLE ML : ISOLATION FOREST
# =====================================================

def score_ml(df):
    model = IsolationForest(n_estimators=200, contamination=ML_CONTAMINATION,
                            random_state=42)
    X = df[ML_FEATURES].to_numpy(dtype=float)
    model.fit(X)
    raw = -model.score_samples(X)
    df["ml_score"] = ((raw - raw.min()) / (raw.max() - raw.min())).round(3)
    df["ml_flag"] = model.predict(X) == -1
    return df


# =====================================================
# RÈGLES : HYPOTHÈSE + VERDICT
# =====================================================

def _matching_plan(row, planning, types):
    t = row["measurement_timestamp"]
    for p in planning:
        if p["type"] not in types:
            continue
        concerned = row["sensor_id"] in p["capteurs"] or p["salle"] == row["room"]
        grace = pd.Timedelta(minutes=PLAN_GRACE_MIN)
        if concerned and p["debut_ts"] <= t <= p["fin_ts"] + grace:
            return p["id"]
    return ""


def classify_row(row, planning, replay_slots):
    """Retourne (hypothèse, détail, verdict, sévérité, plan)."""
    if row["missing"]:
        if row["silence_run"] < SILENCE_MIN_CYCLES:
            return "normal", "Perte isolée d'un message", "normal", "", ""
        plan = _matching_plan(row, planning, ("maintenance",))
        if plan:
            return ("planned_event", "Silence pendant une maintenance planifiée",
                    "probablement_normal", "Faible", plan)
        slot = (row["sensor_id"], row["measurement_timestamp"].floor("5min"))
        if slot in replay_slots:
            return ("buffer_replay", "Silence comblé ensuite par le rejeu du tampon",
                    "probablement_normal", "Faible", "")
        return "sensor_failure", "Capteur muet (silence prolongé)", "a_traiter", "Élevé", ""

    if row["out_of_range"]:
        return "sensor_failure", "Valeur physiquement impossible", "a_traiter", "Élevé", ""

    if row["mac_unknown"] or row["clone_window"] or row["seq_back_win"] >= 2:
        return ("possible_clone", "Identité incohérente (MAC inconnue ou séquences mêlées)",
                "a_traiter", "Élevé", "")

    if row["replay"]:
        return ("buffer_replay", "Mesure ancienne reçue après reconnexion",
                "probablement_normal", "Faible", "")

    if row["seq_back"] or row["fw_change"]:
        plan = _matching_plan(row, planning, ("maintenance",))
        if plan:
            return ("planned_event", "Redémarrage pendant une maintenance planifiée",
                    "probablement_normal", "Faible", plan)
        return "sensor_failure", "Redémarrage non planifié", "a_traiter", "Faible", ""

    if row["identical_run"] >= STUCK_MIN_REPEAT:
        return "sensor_failure", "Valeur figée", "a_traiter", "Modéré", ""

    if pd.notna(row["dev_room_smooth"]) and abs(row["dev_room_smooth"]) >= DRIFT_THRESHOLD:
        return "drift", "Écart durable à la médiane de la salle", "a_traiter", "Modéré", ""

    spike = pd.notna(row["z_self"]) and abs(row["z_self"]) >= SPIKE_Z
    if spike or row["ml_flag"]:
        plan = _matching_plan(row, planning, ("evenement", "maintenance"))
        if plan:
            return ("planned_event", "Variation pendant un événement planifié",
                    "probablement_normal", "Faible", plan)
        if spike:
            return "unknown", "Saut de valeur inhabituel", "a_traiter", "Modéré", ""
        return "unknown", "Combinaison inhabituelle (score ML seul)", "a_traiter", "Faible", ""

    return "normal", "", "normal", "", ""


def classify_events(df, planning):
    replay_rows = df[df["replay"]]
    replay_slots = set(zip(replay_rows["sensor_id"],
                           replay_rows["measurement_timestamp"].dt.floor("5min")))
    out = df.apply(lambda r: classify_row(r, planning, replay_slots),
                   axis=1, result_type="expand")
    df["hypothese"], df["detail"], df["verdict"], df["severite"], df["plan_id"] = (
        out[0], out[1], out[2], out[3], out[4])
    return df


# =====================================================
# REGROUPEMENT EN ALERTES
# =====================================================

def _indices(grp, inventory_row):
    """Faits calculés par Python, présentés à l'opérateur et au LLM."""
    unit = grp["unit"].iloc[0]
    facts = []
    vals = grp["value"].dropna()
    if not vals.empty:
        facts.append(f"Valeurs observées : min {vals.min():g} / max {vals.max():g} {unit}")
    if grp["missing"].any():
        n = int(grp["missing"].sum())
        facts.append(f"{n} message(s) no_data, soit {n * 5} min sans mesure")
    if grp["out_of_range"].any():
        lo, hi = PHYS_RANGE[grp["sensor_type"].iloc[0]]
        facts.append(f"{int(grp['out_of_range'].sum())} valeur(s) hors plage plausible ({lo} à {hi} {unit})")
    if grp["identical_run"].max() >= STUCK_MIN_REPEAT:
        facts.append(f"Même valeur répétée {int(grp['identical_run'].max())} fois de suite")
    dev = grp["dev_room_smooth"].dropna()
    if not dev.empty and dev.abs().max() >= 0.5:
        facts.append(f"Écart moyen à la médiane de la salle : jusqu'à {dev.loc[dev.abs().idxmax()]:+.2f} {unit}")
    macs = sorted(set(grp.loc[grp["mac"] != "", "mac"]))
    if grp["mac_unknown"].any() or len(macs) > 1:
        facts.append(f"Adresses MAC observées : {', '.join(macs)} ; attendue (inventaire) : {inventory_row.get('mac', '?')}")
    if grp["seq_back"].any():
        facts.append(f"Numéro de séquence en recul {int(grp['seq_back'].sum())} fois")
    if grp["fw_change"].any():
        facts.append(f"Changement de firmware vers {grp.loc[grp['fw_change'], 'firmware'].iloc[0]}")
    if grp["replay"].any():
        facts.append(f"Retard mesure/réception : {grp['delay_min'].max():.0f} min max, "
                     f"statut réseau « reconnected »")
    if grp["plan_id"].ne("").any():
        facts.append(f"Planning correspondant : {', '.join(sorted(set(grp['plan_id']) - {''}))}")
    facts.append(f"Score ML (Isolation Forest) : max {grp['ml_score'].max():.2f}, "
                 f"{int(grp['ml_flag'].sum())}/{len(grp)} message(s) jugés atypiques")
    return facts


def build_alerts(df, inventory):
    cand = df[df["verdict"] != "normal"].sort_values(
        ["sensor_id", "hypothese", "verdict", "measurement_timestamp"])
    if cand.empty:
        return pd.DataFrame()

    key_change = (
        (cand["sensor_id"] != cand["sensor_id"].shift())
        | (cand["hypothese"] != cand["hypothese"].shift())
        | (cand["verdict"] != cand["verdict"].shift())
        | (cand["measurement_timestamp"].diff() > pd.Timedelta(minutes=ALERT_GAP_MIN))
    )
    cand = cand.assign(_group=key_change.cumsum())
    inv = inventory.set_index("sensor_id").to_dict("index")

    alerts = []
    for _, grp in cand.groupby("_group"):
        first = grp.iloc[0]
        sev = max(grp["severite"], key=lambda s: SEVERITY_WEIGHT.get(s, 0))
        score_max = float(grp["ml_score"].max())
        prio = SEVERITY_WEIGHT[sev] + 40 * score_max
        if first["verdict"] == "probablement_normal":
            prio *= 0.3
        alerts.append({
            "sensor_id": first["sensor_id"],
            "sensor_type": first["sensor_type"],
            "unit": first["unit"],
            "room": first["room"],
            "hypothese": first["hypothese"],
            "detail": grp["detail"].mode().iloc[0],
            "verdict": first["verdict"],
            "severite": sev,
            "debut": grp["measurement_timestamp"].min(),
            "fin": grp["measurement_timestamp"].max(),
            "n_events": len(grp),
            "score_ml_max": round(score_max, 2),
            "priorite": int(round(prio)),
            "plan_ids": sorted(set(grp["plan_id"]) - {""}),
            "injection": bool(grp["injection"].any()),
            "device_msgs": sorted(set(grp.loc[grp["device_msg"] != "", "device_msg"]))[:3],
            "indices": _indices(grp, inv.get(first["sensor_id"], {})),
            "event_ids": grp["event_id"].tolist(),
        })

    alerts = pd.DataFrame(alerts).sort_values(["debut", "sensor_id"]).reset_index(drop=True)
    alerts.insert(0, "alert_id", [f"ALR-{i:03d}" for i in range(1, len(alerts) + 1)])
    return alerts


def run_pipeline():
    data = load_data()
    df = compute_features(data["raw"], data["inventory"])
    df = score_ml(df)
    df = classify_events(df, data["planning"])
    data["events"] = df
    data["alerts"] = build_alerts(df, data["inventory"])
    return data


# =====================================================
# ÉVALUATION (utilise la vérité terrain)
# =====================================================

def _safe_div(a, b):
    return round(a / b, 3) if b else 0.0


def evaluate_detection(data):
    df, alerts = data["events"], data["alerts"]
    ref = data["references"]
    m = df[["event_id", "sensor_id", "hypothese", "verdict"]].merge(ref, on="event_id")

    m["pred_class"] = np.where(
        m["verdict"] == "normal", "normal",
        np.where(m["verdict"] == "probablement_normal", "false_alarm", m["hypothese"]))
    truth_inc = m["label"].isin(INCIDENT_LABELS)
    pred_inc = m["verdict"] == "a_traiter"

    tp = int((truth_inc & pred_inc).sum())
    fp = int((~truth_inc & pred_inc).sum())
    fn = int((truth_inc & ~pred_inc).sum())
    tn = int((~truth_inc & ~pred_inc).sum())
    precision, recall = _safe_div(tp, tp + fp), _safe_div(tp, tp + fn)
    events_metrics = {
        "vrais_positifs": tp, "faux_positifs": fp, "faux_negatifs": fn,
        "vrais_negatifs": tn, "precision": precision, "rappel": recall,
        "f1": _safe_div(2 * precision * recall, precision + recall),
    }

    per_class = []
    for label in INCIDENT_LABELS:
        sub = m[m["label"] == label]
        per_class.append({
            "classe": label,
            "evenements": len(sub),
            "detectes": int((sub["verdict"] == "a_traiter").sum()),
            "bien_types": int((sub["pred_class"] == label).sum()),
            "rappel": _safe_div((sub["verdict"] == "a_traiter").sum(), len(sub)),
        })
    fa = m[m["label"] == "false_alarm"]
    per_class.append({
        "classe": "false_alarm",
        "evenements": len(fa),
        "detectes": int((fa["verdict"] == "a_traiter").sum()),
        "bien_types": int((fa["verdict"] != "a_traiter").sum()),
        "rappel": _safe_div((fa["verdict"] != "a_traiter").sum(), len(fa)),
    })

    # --- Comparaison des approches (le ML seul, les règles sans contexte, la chaîne) ---
    approaches = []
    for name, pred in [
        ("ML seul (Isolation Forest)", df.set_index("event_id").loc[m["event_id"], "ml_flag"].values),
        ("Règles sans planning ni rejeu", (m["verdict"] != "normal").values),
        ("Chaîne complète (ML + règles + contexte)", pred_inc.values),
    ]:
        p_tp = int((truth_inc.values & pred).sum())
        p_fp = int((~truth_inc.values & pred).sum())
        p_fn = int((truth_inc.values & ~pred).sum())
        fa_raised = int((m["label"].eq("false_alarm").values & pred).sum())
        approaches.append({
            "approche": name, "precision": _safe_div(p_tp, p_tp + p_fp),
            "rappel": _safe_div(p_tp, p_tp + p_fn), "faux_positifs": p_fp,
            "fausses_alertes_levees": fa_raised,
        })

    confusion = pd.crosstab(m["label"], m["pred_class"],
                            rownames=["Référence"], colnames=["Prédiction"])

    # --- Niveau épisode : ce qui compte pour l'équipe d'exploitation ---
    episodes = []
    to_treat = alerts[alerts["verdict"] == "a_traiter"] if not alerts.empty else alerts
    matched_alerts = set()
    for sc in data["scenarios"]:
        start, end = pd.Timestamp(sc["debut"]), pd.Timestamp(sc["fin"])
        ov = alerts[alerts["sensor_id"].isin(sc["capteurs"])
                    & (alerts["debut"] <= end) & (alerts["fin"] >= start)]
        ov_treat = ov[ov["verdict"] == "a_traiter"]
        if sc["type"] == "incident":
            matched_alerts.update(ov_treat["alert_id"])
            detected = not ov_treat.empty
            delay = ((ov_treat["debut"].min() - start).total_seconds() / 60
                     if detected else None)
            ok = detected
            result = "détecté" if detected else "manqué"
            typed = bool((ov_treat["hypothese"] == sc["label"]).any())
        else:
            ok = ov_treat.empty
            delay = None
            typed = None
            if ok:
                result = ("signalée probablement normale"
                          if not ov.empty else "aucune alerte")
            else:
                result = "alerte à tort"
        episodes.append({
            "scenario": sc["scenario_id"], "type": sc["type"], "titre": sc["titre"],
            "attendu": sc["attendu"], "resultat": result, "conforme": ok,
            "bien_type": typed,
            "delai_detection_min": None if delay is None else round(delay),
            "alertes": ", ".join(ov["alert_id"]),
        })
    episodes = pd.DataFrame(episodes)

    false_alerts = (to_treat[~to_treat["alert_id"].isin(matched_alerts)]
                    if not to_treat.empty else to_treat)

    inc = episodes[episodes["type"] == "incident"]
    nonc = episodes[episodes["type"] != "incident"]
    summary = {
        "incidents_detectes": int(inc["conforme"].sum()),
        "incidents_total": len(inc),
        "incidents_manques": inc.loc[~inc["conforme"], "scenario"].tolist(),
        "fausses_alertes_ecartees": int(nonc["conforme"].sum()),
        "fausses_alertes_total": len(nonc),
        "alertes_a_traiter": len(to_treat),
        "alertes_declenchees_a_tort": len(false_alerts),
        "alertes_probablement_normales": int((alerts["verdict"] == "probablement_normal").sum())
        if not alerts.empty else 0,
    }
    return {"resume": summary, "evenements": events_metrics,
            "par_classe": pd.DataFrame(per_class), "confusion": confusion,
            "approches": pd.DataFrame(approaches),
            "episodes": episodes, "alertes_a_tort": false_alerts}


if __name__ == "__main__":
    data = run_pipeline()
    res = evaluate_detection(data)
    print(json.dumps(res["resume"], ensure_ascii=False, indent=2))
    print(json.dumps(res["evenements"], ensure_ascii=False, indent=2))
    print(res["par_classe"].to_string(index=False))
    print(res["approches"].to_string(index=False))
    print(res["episodes"][["scenario", "resultat", "bien_type", "delai_detection_min", "alertes"]].to_string(index=False))
    cols = ["alert_id", "sensor_id", "hypothese", "detail", "verdict", "n_events", "score_ml_max", "priorite"]
    print(data["alerts"][cols].to_string(index=False))
