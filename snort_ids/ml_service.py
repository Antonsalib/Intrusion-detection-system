from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from pathlib import Path
import joblib
import numpy as np
import uvicorn
import json
import os
from typing import Any, Dict

try:
    from tensorflow.keras.models import load_model
except Exception:
    load_model = None


class EventIn(BaseModel):
    event: Dict[str, Any]


app = FastAPI(title="IDS ML Service")


def load_artifacts():
    models_dir = Path(__file__).parent / 'models'
    model = None
    scaler = None
    encoders = {}
    if (models_dir / 'kdd_model.h5').exists() and load_model is not None:
        model = load_model(models_dir / 'kdd_model.h5')
    if (models_dir / 'scaler.pkl').exists():
        scaler = joblib.load(models_dir / 'scaler.pkl')
    for nm in ['protocol_type_enc.pkl', 'service_enc.pkl', 'flag_enc.pkl']:
        p = models_dir / nm
        if p.exists():
            encoders[nm.split('_enc')[0]] = joblib.load(p)
    return model, scaler, encoders


MODEL, SCALER, ENCODERS = load_artifacts()


def features_from_event(event: Dict[str, Any]):
    """Produce a feature vector matching the exact 41 KDD99 features used in training."""
    
    proto = str(event.get('proto', '')).upper()
    dst_port = int(event.get('dst_port') or 0)
    src_bytes = int(event.get('src_bytes') or 0)
    dst_bytes = int(event.get('dst_bytes') or 0)
    
    # Encode protocol_type (0=tcp, 1=udp, 2=icmp, 3=other)
    if proto == 'TCP':
        protocol_type = 0
    elif proto == 'UDP':
        protocol_type = 1
    elif proto == 'ICMP':
        protocol_type = 2
    else:
        protocol_type = 3
    
    # Map destination port to service (0-50 categories)
    service_map = {
        20: 0, 21: 1, 22: 2, 23: 3, 25: 4, 53: 5, 69: 6, 79: 7, 80: 8, 110: 9,
        111: 10, 113: 11, 135: 12, 139: 13, 143: 14, 179: 15, 389: 16, 427: 17,
        443: 18, 445: 19, 465: 20, 513: 21, 514: 22, 515: 23, 543: 24, 544: 25,
        548: 26, 554: 27, 587: 28, 631: 29, 636: 30, 646: 31, 873: 32, 902: 33,
        989: 34, 990: 35, 993: 36, 995: 37, 1433: 38, 1521: 39, 3306: 40, 3389: 41,
        5432: 42, 5984: 43, 6379: 44, 8080: 45, 8443: 46, 9200: 47, 27017: 48, 50500: 49
    }
    service = service_map.get(dst_port, 50)
    
    # Build 41-feature vector in exact KDD order
    vec = [
        0.0,  # 0: duration
        float(protocol_type),  # 1: protocol_type
        float(service),  # 2: service
        0.0,  # 3: flag
        float(src_bytes),  # 4: src_bytes
        float(dst_bytes),  # 5: dst_bytes
        0.0,  # 6: land
        0.0,  # 7: wrong_fragment
        0.0,  # 8: urgent
        0.0,  # 9: hot
        0.0,  # 10: num_failed_logins
        0.0,  # 11: logged_in
        0.0,  # 12: num_compromised
        0.0,  # 13: root_shell
        0.0,  # 14: su_attempted
        0.0,  # 15: num_root
        0.0,  # 16: num_file_creations
        0.0,  # 17: num_shells
        0.0,  # 18: num_access_files
        0.0,  # 19: num_outbound_cmds
        0.0,  # 20: is_host_login
        0.0,  # 21: is_guest_login
        1.0,  # 22: count
        1.0,  # 23: srv_count
        0.0,  # 24: serror_rate
        0.0,  # 25: srv_serror_rate
        0.0,  # 26: rerror_rate
        0.0,  # 27: srv_rerror_rate
        1.0,  # 28: same_srv_rate
        0.0,  # 29: diff_srv_rate
        0.0,  # 30: srv_diff_host_rate
        1.0,  # 31: dst_host_count
        1.0,  # 32: dst_host_srv_count
        1.0,  # 33: dst_host_same_srv_rate
        0.0,  # 34: dst_host_diff_srv_rate
        1.0,  # 35: dst_host_same_src_port_rate
        0.0,  # 36: dst_host_srv_diff_host_rate
        0.0,  # 37: dst_host_serror_rate
        0.0,  # 38: dst_host_srv_serror_rate
        0.0,  # 39: dst_host_rerror_rate
        0.0,  # 40: dst_host_srv_rerror_rate
    ]
    
    assert len(vec) == 41, f"Feature vector has {len(vec)} elements, expected 41"
    return np.array(vec, dtype=float).reshape(1, -1)


@app.post('/score')
def score(event_in: EventIn):
    if MODEL is None or SCALER is None:
        raise HTTPException(status_code=503, detail='ML artifacts not available')
    evt = event_in.event
    try:
        X = features_from_event(evt)
        Xs = SCALER.transform(X)
        prob = float(MODEL.predict(Xs, verbose=0).ravel()[0])
        return {'ml_score': prob, 'ml_label': 1 if prob > 0.5 else 0}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == '__main__':
    uvicorn.run(app, host='127.0.0.1', port=8000)
