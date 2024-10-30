// JavaScript to set prediction box color based on prediction outcome
function updatePrediction(prediction) {
    const predictionBox = document.getElementById('predictionBox');
    const predictionResult = document.getElementById('predictionResult');

    // Set text content
    predictionResult.textContent = prediction;

    // Apply conditional styling based on prediction outcome
    if (prediction.toLowerCase() === "legitimate") {
        predictionBox.classList.add('legitimate');
        predictionBox.classList.remove('malicious');
    } else if (prediction.toLowerCase() === "malicious") {
        predictionBox.classList.add('malicious');
        predictionBox.classList.remove('legitimate');
    }
}

// Example usage
updatePrediction("Malicious"); // or "Legitimate"
