document.getElementById('scannerForm').addEventListener('submit', function (e) {
    e.preventDefault();
    const url = document.getElementById('websiteUrl').value.trim();

    if (!url) {
        alert("Please enter a valid website URL.");
        return;
    }

    fetch('/api/scan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: url })
    })
        .then(response => response.json())
        .then(data => {
            document.getElementById('domain').innerText = data.domain || "N/A";
            document.getElementById('trustscore').innerText = data.trustscore || "N/A";
            document.getElementById('scam_detected').innerText = (data.scam_detected === "High" || data.scam_detected === true) ? 'Yes' : 'No';
            document.getElementById('violations').innerText = (data.violations || []).join(", ") || "None";
            document.getElementById('ip').innerText = data.ip || "N/A";
            document.getElementById('reverse_dns').innerText = data.reverse_dns || "N/A";
            document.getElementById('asn').innerText = `${data.asn || "N/A"} - ${data.asn_description || ""}`;
            document.getElementById('isp').innerText = data.isp_org || "N/A";
            document.getElementById('country').innerText = data.country || "N/A";
            document.getElementById('ssl_valid').innerText = data.ssl_valid ? 'Valid' : 'Invalid';
            document.getElementById('ssl_expiry').innerText = data.cert_expiry ? `${data.cert_expiry} (${data.cert_days_remaining} days left)` : "N/A";
            document.getElementById('headers').innerText = (data.missing_headers || []).join(", ") || "None";
            document.getElementById('domain_age').innerText = data.domain_age_days ? `${data.domain_age_days} days` : "N/A";
            document.getElementById('registrar').innerText = data.domain_registrar || "N/A";
            document.getElementById('owner').innerText = data.domain_owner || "N/A";

            // LLM output fields
            document.getElementById('llm_output').innerText = data.llm_output || "No LLM output.";
            document.getElementById('resultSection').style.display = 'block';
        })
        .catch(err => {
            alert("Error fetching data from backend");
            console.error("Backend Error:", err);
        });
});

function showDisclaimer() {
    const disclaimer = document.getElementById('disclaimerText');
    disclaimer.style.display = 'block';
}
