
import joblib
import os
from pathlib import Path
import pandas as pd
import numpy as np

from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split

try:
    from tensorflow.keras import Sequential
    from tensorflow.keras.layers import Dense
except Exception:
    raise RuntimeError("TensorFlow/Keras not available in this environment")


OUT_DIR = Path(__file__).parent / "models"
OUT_DIR.mkdir(parents=True, exist_ok=True)


def load_kdd(path: Path):
    cols = ['duration','protocol_type','service','flag','src_bytes','dst_bytes','land',
            'wrong_fragment','urgent','hot','num_failed_logins','logged_in','num_compromised',
            'root_shell','su_attempted','num_root','num_file_creations','num_shells',
            'num_access_files','num_outbound_cmds','is_host_login','is_guest_login',
            'count','srv_count','serror_rate','srv_serror_rate','rerror_rate','srv_rerror_rate',
            'same_srv_rate','diff_srv_rate','srv_diff_host_rate','dst_host_count','dst_host_srv_count',
            'dst_host_same_srv_rate','dst_host_diff_srv_rate','dst_host_same_src_port_rate',
            'dst_host_srv_diff_host_rate','dst_host_serror_rate','dst_host_srv_serror_rate',
            'dst_host_rerror_rate','dst_host_srv_rerror_rate','label']
    df = pd.read_csv(path, header=None, compression='gzip')
    df.columns = cols
    return df


def preprocess(df: pd.DataFrame):
    df = df.copy()
    # encode categorical columns
    encoders = {}
    for col in ['protocol_type', 'service', 'flag']:
        enc = LabelEncoder()
        df[col] = enc.fit_transform(df[col].astype(str))
        encoders[col] = enc

    df['label'] = df['label'].apply(lambda x: 0 if str(x).strip() == 'normal.' else 1)

    X = df.drop('label', axis=1)
    y = df['label'].values

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.3, random_state=42)
    return X_train, X_test, y_train, y_test, scaler, encoders


def build_model(input_dim: int):
    model = Sequential([
        Dense(32, activation='relu', input_shape=(input_dim,)),
        Dense(16, activation='relu'),
        Dense(1, activation='sigmoid')
    ])
    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    return model


def main():
    src = Path('ids_env/kddcup.data_10_percent.gz')
    if not src.exists():
        raise FileNotFoundError(f"KDD data not found at {src}")
    print('Loading dataset...')
    df = load_kdd(src)
    print('Preprocessing...')
    X_train, X_test, y_train, y_test, scaler, encoders = preprocess(df)

    print('Building model...')
    model = build_model(X_train.shape[1])
    print('Training (this may take a bit)...')
    model.fit(X_train, y_train, epochs=5, batch_size=128, validation_split=0.1, verbose=1)

    print('Saving artifacts...')
    model.save(OUT_DIR / 'kdd_model.h5')
    joblib.dump(scaler, OUT_DIR / 'scaler.pkl')
    for k, v in encoders.items():
        joblib.dump(v, OUT_DIR / f'{k}_enc.pkl')

    # quick evaluation
    loss, acc = model.evaluate(X_test, y_test, verbose=0)
    print(f'Test accuracy: {acc:.4f}')


if __name__ == '__main__':
    main()
