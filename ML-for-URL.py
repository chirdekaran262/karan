import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score
import joblib

# Load the dataset
data = pd.read_csv('phishing.csv')  # Make sure the filename is correct

# Separate features and target variable
X = data.drop(columns=['Result'])  # Ensure 'Result' is the correct target column name
y = data['Result']

# Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Initialize and train the Decision Tree model
model = DecisionTreeClassifier(random_state=42)
model.fit(X_train, y_train)

# Evaluate the model
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"Model Accuracy: {accuracy * 100:.2f}%")

# Save the model
joblib.dump(model, 'url_classifier_model.joblib')
print("Model saved as 'url_classifier_model.joblib'")

print(data.shape)  # This will show the number of rows and columns
print(data.columns) 