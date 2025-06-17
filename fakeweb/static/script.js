document.getElementById('scannerForm').addEventListener('submit', function(e) {
    e.preventDefault();
    const url = document.getElementById('websiteUrl').value;

    fetch('/api/scan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: url })
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById('domain').innerText = data.domain;
        document.getElementById('trustscore').innerText = data.trustscore;
        document.getElementById('scam_detected').innerText = data.scam_detected ? 'Yes' : 'No';
        document.getElementById('violations').innerText = data.violations.join(", ");
        document.getElementById('ip').innerText = data.ip || "N/A";
        document.getElementById('ssl_valid').innerText = data.ssl_valid ? 'Valid' : 'Invalid';
        document.getElementById('headers').innerText = data.missing_headers.join(", ");
        document.getElementById('rating').innerText = data.rating;
        document.getElementById('reviews').innerText = data.reviews;
        document.getElementById('angry').innerText = data.feelings.angry;
        document.getElementById('neutral').innerText = data.feelings.neutral;
        document.getElementById('happy').innerText = data.feelings.happy;
        document.getElementById('very_happy').innerText = data.feelings.very_happy;

        document.getElementById('resultSection').style.display = 'block';
    })
    .catch(err => {
        alert("Error fetching data from backend");
        console.error(err);
    });
});

function showDisclaimer() {
  const disclaimer = document.getElementById('disclaimerText');
  disclaimer.style.display = 'block';
}