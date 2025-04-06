import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score
from torch.utils.tensorboard import SummaryWriter
import joblib
import numpy as np
import os

# Set environment variable to disable oneDNN custom operations
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'

# Load dataset
df = pd.read_csv(r"ransomware_dataset.csv")
df = df.drop(columns=['FileName', 'md5Hash'])
X = df.drop(columns=['Benign'])
y = df['Benign']

# Scale the features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Split data into training and test sets
X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.3, random_state=42)

# Initialize TensorBoard writer
writer = SummaryWriter(log_dir="runs/ransomware_detection")

# Train the RandomForestClassifier and log metrics
model = RandomForestClassifier(n_estimators=100, random_state=42)
for epoch in range(10):  # Train for 10 epochs
    model.fit(X_train, y_train)
    y_pred_train = model.predict(X_train)
    y_pred_test = model.predict(X_test)

    # Calculate metrics
    train_accuracy = accuracy_score(y_train, y_pred_train)
    test_accuracy = accuracy_score(y_test, y_pred_test)
    train_precision = precision_score(y_train, y_pred_train)
    test_precision = precision_score(y_test, y_pred_test)
    train_recall = recall_score(y_train, y_pred_train)
    test_recall = recall_score(y_test, y_pred_test)

    # Log metrics to TensorBoard
    writer.add_scalar('Accuracy/Train', train_accuracy, epoch)
    writer.add_scalar('Accuracy/Test', test_accuracy, epoch)
    writer.add_scalar('Precision/Train', train_precision, epoch)
    writer.add_scalar('Precision/Test', test_precision, epoch)
    writer.add_scalar('Recall/Train', train_recall, epoch)
    writer.add_scalar('Recall/Test', test_recall, epoch)

    # Log feature importance as a histogram
    feature_importance = model.feature_importances_
    writer.add_histogram('Feature Importance', np.array(feature_importance), epoch)

# Save the trained model and scaler
joblib.dump(model, 'ransomware_model.pkl')
joblib.dump(scaler, 'scaler.pkl')

print("Model and scaler saved successfully!")

# Close TensorBoard writer
writer.close()