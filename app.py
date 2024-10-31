# import os
# from flask import Flask, request, render_template, redirect, url_for, flash
# import joblib
# import pefile

# # Initialize Flask app
# app = Flask(__name__)
# app.config['UPLOAD_FOLDER'] = 'uploads/'
# app.secret_key = 'supersecretkey'  # For flashing messages

# # Create the uploads folder if it doesn't exist
# if not os.path.exists(app.config['UPLOAD_FOLDER']):
#     os.makedirs(app.config['UPLOAD_FOLDER'])

# # Function to extract PE header features from an executable file
# def extract_pe_features(file_path):
#     try:
#         pe = pefile.PE(file_path)
        
#         # Extract some basic features from the PE header (you can add more)
#         features = [
#             pe.FILE_HEADER.Machine,
#             pe.FILE_HEADER.NumberOfSections,
#             pe.OPTIONAL_HEADER.SizeOfHeaders,
#             pe.OPTIONAL_HEADER.SizeOfImage,
#             pe.OPTIONAL_HEADER.AddressOfEntryPoint,
#         ]
#         return features
#     except Exception as e:
#         print(f"Error reading file {file_path}: {e}")
#         return None

# # Load the saved model
# model = joblib.load('malware_detection_model.pkl')

# # Route for the homepage
# @app.route('/')
# def index():
#     return render_template('index.html')

# # Route for file upload and prediction
# @app.route('/upload', methods=['POST'])
# def upload_file():
#     if 'file' not in request.files:
#         flash('No file part')
#         return redirect(request.url)
    
#     file = request.files['file']
    
#     if file.filename == '':
#         flash('No selected file')
#         return redirect(request.url)
    
#     if file:
#         # Save the file
#         file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
#         file.save(file_path)
        
#         # Extract features and predict
#         features = extract_pe_features(file_path)
#         if features is None:
#             flash('Error extracting features from the file. Please upload a valid PE file.')
#             return redirect(url_for('index'))
        
#         # Predict using the model
#         prediction = model.predict([features])
#         result = 'Malware' if prediction[0] == 1 else 'Benign'
        
#         flash(f'This file is classified as: {result}')
#         return redirect(url_for('index'))

# # Run the Flask app
# if __name__ == '__main__':
#     app.run(debug=True)

from flask import Flask, request, render_template
import subprocess
import os
import logging
import joblib
from url_classifier import extract_features  # Import your feature extraction function
from urllib.parse import urlparse

# Initialize Flask app
app = Flask(__name__)

# Set upload folder and create it if it doesn't exist
UPLOAD_FOLDER = './uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Configure logging
logging.basicConfig(level=logging.INFO)

# Load the saved URL classifier model
model = joblib.load('url_classifier_model.joblib')

@app.route('/', methods=['GET', 'POST'])
def index():
    file_prediction = None
    url_prediction = None
    
    if request.method == 'POST':
        # File Classification Logic
        if 'file' in request.files:
            file = request.files['file']
            logging.info("File upload received.")
            if file:
                # Save file to the upload folder
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
                file.save(file_path)
                logging.info(f"File saved to {file_path}")

                # Run the external script and capture its output
                result = subprocess.run(['python', 'pe_classifier.py', file_path], capture_output=True, text=True)
                file_prediction = result.stdout.strip() if result.returncode == 0 else f"Error: {result.stderr.strip()}"
                logging.info(f"File classification result: {file_prediction}")

        # URL Classification Logic
        if 'url' in request.form:
            url = request.form['url']
            logging.info(f"URL received for classification: {url}")

            # Validate URL format
            parsed_url = urlparse(url)
            if not parsed_url.scheme or not parsed_url.netloc:
                url_prediction = "Invalid URL format."
                logging.warning(f"Invalid URL: {url}")
            else:
                try:
                    # Extract features from the URL
                    features = extract_features(url)

                    # Predict using the loaded model
                    url_result = model.predict(features)  # Assuming features are in the correct format
                    print("for checking purpose",url_result)
                    # Classify the result based on the three possible outputs
                    if url_result == 1:
                        url_prediction = "Legitimate URL"
                    elif url_result == 0:
                        url_prediction = "Suspicious URL"
                    else:
                        url_prediction = "Malicious URL"

                    logging.info(f"URL classification result: {url_prediction}")
                except Exception as e:
                    url_prediction = "Error in URL classification."
                    logging.error(f"Error during URL classification: {e}")

    return render_template('index.html', prediction=file_prediction, url_prediction=url_prediction)

if __name__ == '__main__':
    app.run(debug=True)
