import joblib
import pickle
from sklearn.feature_selection import SelectFromModel
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score
import pandas as pd
import numpy as np

# Load the dataset
df = pd.read_csv('malware.csv', sep='|')
df.fillna(df.select_dtypes(include=[np.number]).mean(), inplace=True)  # For numerical columns
df.fillna(df.select_dtypes(include=[object]).mode().iloc[0], inplace=True)  # For categorical columns

# Prepare features and labels
X = df.drop(['Name', 'md5', 'legitimate'], axis=1).values
y = df['legitimate'].values

# Split data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Standardize the features
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Feature selection
extratrees = ExtraTreesClassifier().fit(X_train_scaled, y_train)
feature_selector = SelectFromModel(extratrees, prefit=True)
X_train_new = feature_selector.transform(X_train_scaled)
X_test_new = feature_selector.transform(X_test_scaled)

# Save the feature selector
joblib.dump(feature_selector, 'feature_selector.pkl')

# Train and save the classifier
decision_tree = DecisionTreeClassifier()
decision_tree.fit(X_train_new, y_train)
joblib.dump(decision_tree, 'classifier.pkl')

# Save the scaler
joblib.dump(scaler, 'scaler.pkl')

# Save selected feature names
selected_features = [df.columns[i] for i in feature_selector.get_support(indices=True)]
with open('features.pkl', 'wb') as f:
    pickle.dump(selected_features, f)

# Predict and calculate accuracy on the test set
y_pred = decision_tree.predict(X_test_new)
accuracy = accuracy_score(y_test, y_pred)
print(f'Model accuracy on the test set: {accuracy * 100:.2f}%')
