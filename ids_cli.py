# ---------------------------
# IDS Prototype - Command Line Version
# ---------------------------

import os
import pandas as pd
import tensorflow as tf
from tensorflow.keras import Sequential
from tensorflow.keras.layers import Dense
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, ConfusionMatrixDisplay
import matplotlib.pyplot as plt

# ---------------------------
# Suppress TensorFlow INFO logs
# ---------------------------
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'  # hides INFO logs
tf.get_logger().setLevel('ERROR')

# ---------------------------
# Step 1: Load dataset
# ---------------------------
print("Loading dataset...")
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
print("Dataset loaded. Shape:", df.shape)

# ---------------------------
# Step 2: Preprocess data
# ---------------------------
print("Preprocessing data...")
df = pd.get_dummies(df, columns=['protocol_type','service','flag'])
df['label'] = df['label'].apply(lambda x: 0 if x == 'normal.' else 1)

X = df.drop('label', axis=1)
y = df['label']

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.3, random_state=42
)
print("Preprocessing done.")

# ---------------------------
# Step 3: Build and train model
# ---------------------------
print("Building and training neural network...")
model = Sequential([
    Dense(64, activation='relu', input_shape=(X_train.shape[1],)),
    Dense(32, activation='relu'),
    Dense(1, activation='sigmoid')
])
model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

# Train the model
model.fit(X_train, y_train, epochs=10, batch_size=32, validation_split=0.1, verbose=1)
print("Training complete.")

# ---------------------------
# Step 4: Make predictions
# ---------------------------
print("Making predictions on test set...")
y_pred_prob = model.predict(X_test)
y_pred = (y_pred_prob > 0.5).astype(int)

# ---------------------------
# Step 5: Print metrics to terminal
# ---------------------------
print("\nClassification Report:")
print(classification_report(y_test, y_pred))

# ---------------------------
# Step 6: Save results to CSV
# ---------------------------
results = pd.DataFrame({
    "Actual": y_test,
    "Predicted": y_pred.flatten(),
    "Probability": y_pred_prob.flatten()
})
results.to_csv("ids_results.csv", index=False)
print("Predictions saved to ids_results.csv")

# ---------------------------
# Step 7: Save classification report to TXT
# ---------------------------
report = classification_report(y_test, y_pred)
with open("ids_report.txt", "w") as f:
    f.write(report)
print("Classification report saved to ids_report.txt")

# ---------------------------
# Step 8: Plot and save confusion matrix
# ---------------------------
cm = confusion_matrix(y_test, y_pred)
disp = ConfusionMatrixDisplay(cm, display_labels=["Normal", "Attack"])
fig, ax = plt.subplots(figsize=(6,6))
disp.plot(cmap=plt.cm.Blues, ax=ax)
plt.title("Confusion Matrix")
plt.savefig("ids_confusion_matrix.png")
plt.close(fig)  # close plot to avoid GUI pop-up
print("Confusion matrix saved to ids_confusion_matrix.png")

print("\nAll done!")
