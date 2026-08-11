"""Converts parsed HTTP events into numerical feature vectors for ML."""
import numpy as np

def extract_features(ev):
    """Extracts 5 key numerical features from an HTTP event."""
    uri_len = len(ev.get("uri_path", ""))
    query = ev.get("uri_query", "")
    query_len = len(query)
    num_params = len(ev.get("query_params", {}))
    status = ev.get("status_code", 200)
    res_bytes = ev.get("response_bytes", 0)
    
    return np.array([[uri_len, query_len, num_params, status, res_bytes]])
