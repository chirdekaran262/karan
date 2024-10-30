# Malware Detection System

## Overview
This project implements a malware detection system using machine learning techniques. It classifies Portable Executable (PE) files as legitimate or malicious based on extracted features. The system utilizes a Decision Tree classifier, feature selection via Extra Trees, and standardization of input features for improved accuracy.

## Features
- Upload PE files for classification.
- Predict whether the uploaded file is legitimate or malware.
- Displays the prediction result and accuracy of the model.
- Designed with an interactive web interface using Flask and HTML/CSS.

## Technologies Used
- **Backend:** Flask (Python)
- **Machine Learning:** Scikit-learn
- **Data Handling:** Pandas, NumPy
- **Model Serialization:** Joblib, Pickle
- **Frontend:** HTML, CSS
- **Development Environment:** Python 3.x

## Dataset
The model is trained on a dataset of PE files with labeled features. The dataset includes various attributes of the files, which are used to predict their legitimacy.

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/chirdekaran262/Malware-Detection.git
   cd malware-detection
   ```

2. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Prepare the dataset:
   - Place the `malware.csv` file in the root directory.

4. Run the application:
   ```bash
   python app.py
   ```
   Access the application at `http://127.0.0.1:5000/`.

## Usage
1. Open the web application in your browser.
2. Upload a PE file (`.exe` format) using the provided file upload interface.
3. Click the "Classify" button to receive the prediction and accuracy of the model.

## Important Notes
- The model is not 100% accurate; predictions should be used as guidance and not as definitive conclusions about file legitimacy.
- Continuous improvement of the model is needed as new malware samples are discovered.

## License
----------------------------------------------------------------.

## Acknowledgments
- Special thanks to the contributors and the community for their support.
- References to machine learning literature and datasets that guided the project development.
