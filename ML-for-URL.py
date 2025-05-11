import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.feature_selection import SelectFromModel
import matplotlib.pyplot as plt
import seaborn as sns
import joblib

# Load the dataset
data = pd.read_csv('phishing.csv')

# Exploratory Data Analysis
print(f"Dataset shape: {data.shape}")
print(f"Features: {data.columns.tolist()}")
print(f"Class distribution:\n{data['Result'].value_counts()}")

# Check for missing values
print(f"Missing values:\n{data.isnull().sum()}")

# Feature Engineering
X = data.drop(columns=['Result'])
y = data['Result']

# Split the data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Scaling features (important for some algorithms)
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Feature selection using Random Forest to identify most important features
feature_selector = RandomForestClassifier(n_estimators=100, random_state=42)
feature_selector.fit(X_train, y_train)

# Plot feature importance
feature_importance = pd.DataFrame({
    'feature': X.columns,
    'importance': feature_selector.feature_importances_
}).sort_values('importance', ascending=False)

plt.figure(figsize=(10, 6))
sns.barplot(x='importance', y='feature', data=feature_importance[:15])
plt.title('Top 15 Feature Importances')
plt.tight_layout()
plt.savefig('feature_importance.png')

# Select top features (optional)
selector = SelectFromModel(feature_selector, threshold='mean', prefit=True)
X_train_selected = selector.transform(X_train)
X_test_selected = selector.transform(X_test)
selected_features = X.columns[selector.get_support()].tolist()
print(f"Selected {len(selected_features)} features: {selected_features}")

# Model 1: Optimized Random Forest with hyperparameter tuning
rf_params = {
    'n_estimators': [100, 200],
    'max_depth': [None, 20, 30],
    'min_samples_split': [2, 5],
    'min_samples_leaf': [1, 2]
}

rf_grid = GridSearchCV(
    RandomForestClassifier(random_state=42),
    rf_params,
    cv=5,
    scoring='accuracy',
    n_jobs=-1
)
rf_grid.fit(X_train, y_train)
rf_best = rf_grid.best_estimator_

# Evaluate Random Forest model
y_pred_rf = rf_best.predict(X_test)
rf_accuracy = accuracy_score(y_test, y_pred_rf)
print(f"\nRandom Forest Accuracy: {rf_accuracy:.4f}")
print(f"Best parameters: {rf_grid.best_params_}")
print(f"Classification Report:\n{classification_report(y_test, y_pred_rf)}")

# Model 2: Gradient Boosting
gb_params = {
    'n_estimators': [100, 200],
    'learning_rate': [0.05, 0.1],
    'max_depth': [3, 5]
}

gb_grid = GridSearchCV(
    GradientBoostingClassifier(random_state=42),
    gb_params,
    cv=5,
    scoring='accuracy',
    n_jobs=-1
)
gb_grid.fit(X_train, y_train)
gb_best = gb_grid.best_estimator_

# Evaluate Gradient Boosting model
y_pred_gb = gb_best.predict(X_test)
gb_accuracy = accuracy_score(y_test, y_pred_gb)
print(f"\nGradient Boosting Accuracy: {gb_accuracy:.4f}")
print(f"Best parameters: {gb_grid.best_params_}")
print(f"Classification Report:\n{classification_report(y_test, y_pred_gb)}")

# Compare models
print("\nModel Comparison:")
print(f"Decision Tree (Original): -")
print(f"Random Forest: {rf_accuracy:.4f}")
print(f"Gradient Boosting: {gb_accuracy:.4f}")

# Save the best model
best_model = rf_best if rf_accuracy > gb_accuracy else gb_best
model_name = "random_forest_model.joblib" if rf_accuracy > gb_accuracy else "gradient_boosting_model.joblib"
joblib.dump(best_model, model_name)
joblib.dump(scaler, 'scaler.joblib')
print(f"\nBest model saved as '{model_name}'")

# Visualize confusion matrix for the best model
y_pred_best = best_model.predict(X_test)
cm = confusion_matrix(y_test, y_pred_best)
plt.figure(figsize=(8, 6))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
plt.xlabel('Predicted')
plt.ylabel('Actual')
plt.title('Confusion Matrix')
plt.savefig('confusion_matrix.png')