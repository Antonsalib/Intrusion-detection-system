# ---------------------------
# IDS Dashboard with Streamlit
# ---------------------------

import pandas as pd
import tensorflow as tf
from tensorflow.keras import Sequential
from tensorflow.keras.layers import Dense
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, ConfusionMatrixDisplay
import matplotlib.pyplot as plt
import streamlit as st

# ---------------------------
# Title
# ---------------------------
st.title("Intrusion Detection System (IDS) Prototype")

# ---------------------------
# Load Dataset
# ---------------------------
@st.cache_data
def load_data():
    df = pd.read_csv("kddcup.data_10_percent.gz", header=None, compression='gzip')
    columns = ['duration','protocol_type','service','flag','src_bytes','dst_bytes','land',
               'wrong_fragment','urgent','hot','num_failed_logins','logged_in','num_compromised',
               'root_shell','su_attempted','num_root','num_file_creations','num_shells',
               'num_access_files','num_outbound_cmds','is_host_login','is_guest_login',
               'count','srv_count','serror_rate','srv_serror_rate','rerror_rate','srv_rerror_rate',
               'same_srv_rate','diff_srv_rate','srv_diff_host_rate','dst_host_count','dst_host_srv_count',
               'dst_host_same_srv_rate','dst_host_diff_srv_rate','dst_host_same_src_port_rate',
               'dst_host_srv_diff_host_rate','dst_host_serror_rate','dst_host_srv_serror_rate',
               'dst_host_rerror_rate','dst_host_srv_rerror_rate','label']
    df.columns = columns
    return df

df = load_data()
st.write("Dataset loaded successfully. Shape:", df.shape)

# ---------------------------
# Preprocess
# ---------------------------
df = pd.get_dummies(df, columns=['protocol_type','service','flag'])
df['label'] = df['label'].apply(lambda x: 0 if x == 'normal.' else 1)

X = df.drop('label', axis=1)
y = df['label']

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.3, random_state=42
)

# ---------------------------
# Build and Train Model
# ---------------------------
@st.cache_resource
def train_model(X_train, y_train):
    model = Sequential([
        Dense(64, activation='relu', input_shape=(X_train.shape[1],)),
        Dense(32, activation='relu'),
        Dense(1, activation='sigmoid')
    ])
    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    model.fit(X_train, y_train, epochs=10, batch_size=32, validation_split=0.1, verbose=0)
    return model

st.write("Training model...")
model = train_model(X_train, y_train)
st.success("Model trained!")

# ---------------------------
# Predictions
# ---------------------------
y_pred_prob = model.predict(X_test)
y_pred = (y_pred_prob > 0.5).astype(int)

results = pd.DataFrame({
    "Actual": y_test,
    "Predicted": y_pred.flatten(),
    "Probability": y_pred_prob.flatten()
})

st.subheader("Predictions Table")
st.dataframe(results.head(50))  # show first 50 rows

# ---------------------------
# Metrics
# ---------------------------
st.subheader("Classification Metrics")
report = classification_report(y_test, y_pred, output_dict=True)
report_df = pd.DataFrame(report).transpose()
st.dataframe(report_df)

# ---------------------------
# Confusion Matrix
# ---------------------------
st.subheader("Confusion Matrix")
cm = confusion_matrix(y_test, y_pred)
disp = ConfusionMatrixDisplay(cm, display_labels=["Normal", "Attack"])
fig, ax = plt.subplots(figsize=(5,5))
disp.plot(cmap=plt.cm.Blues, ax=ax)
st.pyplot(fig)
