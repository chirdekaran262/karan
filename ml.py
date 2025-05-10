import joblib
import pickle
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.metrics import classification_report
import warnings
warnings.filterwarnings('ignore')

# Load the dataset
print("Loading and preparing the dataset...")
df = pd.read_csv('malware.csv', sep='|')

# Basic data exploration
print(f"Dataset shape: {df.shape}")
print(f"Label distribution:\n{df['legitimate'].value_counts()}")

# Remove md5 and Name columns as they are just identifiers
X = df.drop(['Name', 'md5', 'legitimate'], axis=1)
y = df['legitimate']

# Handle missing values safely
print("Handling missing values...")
# For numeric columns, fill with mean
for col in X.select_dtypes(include=[np.number]).columns:
    X[col].fillna(X[col].mean(), inplace=True)

# For categorical columns (if any)
for col in X.select_dtypes(include=['object']).columns:
    print(f"Found categorical column: {col}")
    if not X[col].mode().empty:
        X[col].fillna(X[col].mode()[0], inplace=True)
    else:
        X[col].fillna("unknown", inplace=True)

# Check for and convert any object columns to numeric if possible
object_cols = X.select_dtypes(include=['object']).columns.tolist()
if object_cols:
    print(f"Converting object columns: {object_cols}")
    for col in object_cols:
        try:
            X[col] = pd.to_numeric(X[col])
        except:
            # Create dummy variables
            print(f"  Cannot convert {col} to numeric, will use one-hot encoding")

# One-hot encode any remaining categorical columns
remaining_object_cols = X.select_dtypes(include=['object']).columns.tolist()
if remaining_object_cols:
    print(f"One-hot encoding remaining categorical columns: {remaining_object_cols}")
    X = pd.get_dummies(X, columns=remaining_object_cols, drop_first=True)

print(f"After preprocessing, feature matrix shape: {X.shape}")

# Split data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

print(f"Training set shape: {X_train.shape}")
print(f"Testing set shape: {X_test.shape}")

# Check class distribution in training set
print(f"Training set class distribution:\n{y_train.value_counts()}")

# Standardize the features
print("Standardizing features...")
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Define the models for evaluation
models = {
    'Decision Tree': DecisionTreeClassifier(random_state=42),
    'Random Forest': RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1),
    'Gradient Boosting': GradientBoostingClassifier(n_estimators=100, random_state=42)
}

# Function to evaluate models
def evaluate_model(name, model, X_train, y_train, X_test, y_test):
    print(f"\nEvaluating {name}...")
    
    # Cross-validation
    cv_scores = cross_val_score(model, X_train, y_train, cv=5, scoring='accuracy')
    print(f"Cross-validation accuracy: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")
    
    # Train the model
    model.fit(X_train, y_train)
    
    # Make predictions
    y_pred = model.predict(X_test)
    
    # Calculate metrics
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, average='weighted')
    recall = recall_score(y_test, y_pred, average='weighted')
    f1 = f1_score(y_test, y_pred, average='weighted')
    
    print(f"Test accuracy: {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall: {recall:.4f}")
    print(f"F1 Score: {f1:.4f}")
    
    # Classification report
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    
    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    print("\nConfusion Matrix:")
    print(cm)
    
    # Feature importance (if available)
    if hasattr(model, 'feature_importances_'):
        importances = model.feature_importances_
        indices = np.argsort(importances)[::-1]
        
        print("\nTop 10 Most Important Features:")
        feature_names = X.columns
        for i in range(min(10, len(importances))):
            print(f"{i+1}. {feature_names[indices[i]]}: {importances[indices[i]]:.4f}")
    
    return model, accuracy, precision, recall, f1

# Evaluate all models
results = {}
for name, model in models.items():
    trained_model, accuracy, precision, recall, f1 = evaluate_model(name, model, X_train_scaled, y_train, X_test_scaled, y_test)
    results[name] = {
        'model': trained_model,
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1
    }

# Compare models
print("\nModel Comparison:")
comparison_df = pd.DataFrame({
    name: {
        'Accuracy': results[name]['accuracy'],
        'Precision': results[name]['precision'],
        'Recall': results[name]['recall'],
        'F1 Score': results[name]['f1']
    } for name in results
})
print(comparison_df)

# Find the best model based on F1 score
best_model_name = max(results, key=lambda x: results[x]['f1'])
best_model = results[best_model_name]['model']
print(f"\nBest model based on F1 score: {best_model_name}")

# Save the best model
print(f"\nSaving the best model ({best_model_name})...")
joblib.dump(best_model, 'best_model.pkl')
joblib.dump(scaler, 'scaler.pkl')

# Save feature names
with open('feature_names.pkl', 'wb') as f:
    pickle.dump(list(X.columns), f)

print("Model training and evaluation complete!")

# Function to make predictions on new data
def predict_malware(data):
    """
    Make predictions on new data using the trained model
    
    Parameters:
        data (pandas.DataFrame): The data to make predictions on
        
    Returns:
        numpy.array: Predictions (1 for legitimate, 0 for malicious)
    """
    # Load the model and preprocessing components
    model = joblib.load('best_model.pkl')
    scaler = joblib.load('scaler.pkl')
    
    # Preprocess the data
    data_scaled = scaler.transform(data)
    
    # Make predictions
    return model.predict(data_scaled)